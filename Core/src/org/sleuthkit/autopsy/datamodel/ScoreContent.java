/*
 * Autopsy Forensic Browser
 *
 * Copyright 2023 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.autopsy.datamodel;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.sql.SQLException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.openide.nodes.AbstractNode;
import org.openide.nodes.ChildFactory;
import org.openide.nodes.Children;
import org.openide.nodes.Node;
import org.openide.nodes.Sheet;
import org.openide.util.NbBundle;
import org.openide.util.NbBundle.Messages;
import org.openide.util.WeakListeners;
import org.openide.util.lookup.Lookups;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.TimeZoneUtils;
import static org.sleuthkit.autopsy.datamodel.AbstractContentNode.NO_DESCR;
import org.sleuthkit.autopsy.guiutils.RefreshThrottler;
import org.sleuthkit.autopsy.ingest.IngestManager;
import org.sleuthkit.autopsy.ingest.IngestManager.IngestModuleEvent;
import org.sleuthkit.autopsy.ingest.ModuleDataEvent;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardArtifact.Category;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.ContentVisitor;
import org.sleuthkit.datamodel.DerivedFile;
import org.sleuthkit.datamodel.Directory;
import org.sleuthkit.datamodel.File;
import org.sleuthkit.datamodel.FsContent;
import org.sleuthkit.datamodel.LayoutFile;
import org.sleuthkit.datamodel.LocalFile;
import org.sleuthkit.datamodel.Score.Priority;
import org.sleuthkit.datamodel.Score.Significance;
import org.sleuthkit.datamodel.SlackFile;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.VirtualDirectory;

/**
 * Score content view nodes.
 */
public class ScoreContent implements AutopsyVisitableItem {

    private SleuthkitCase skCase;
    private final long filteringDSObjId;    // 0 if not filtering/grouping by data source

    @NbBundle.Messages({"ScoreContent_badFilter_text=Bad Items",
        "ScoreContent_susFilter_text=Suspicious Items"})
    public enum ScoreContentFilter implements AutopsyVisitableItem {

        BAD_ITEM_FILTER(0, "BAD_ITEM_FILTER",
                Bundle.ScoreContent_badFilter_text()),
        SUS_ITEM_FILTER(1, "SUS_ITEM_FILTER",
                Bundle.ScoreContent_susFilter_text());

        private int id;
        private String name;
        private String displayName;

        private ScoreContentFilter(int id, String name, String displayName) {
            this.id = id;
            this.name = name;
            this.displayName = displayName;

        }

        public String getName() {
            return this.name;
        }

        public int getId() {
            return this.id;
        }

        public String getDisplayName() {
            return this.displayName;
        }

        @Override
        public <T> T accept(AutopsyItemVisitor<T> visitor) {
            return visitor.visit(this);
        }
    }

    /**
     * Constructor assuming no data source filtering.
     *
     * @param skCase The sleuthkit case.
     */
    public ScoreContent(SleuthkitCase skCase) {
        this(skCase, 0);
    }

    /**
     * Constructor.
     *
     * @param skCase The sleuthkit case.
     * @param dsObjId The data source object id to filter on if > 0.
     */
    public ScoreContent(SleuthkitCase skCase, long dsObjId) {
        this.skCase = skCase;
        this.filteringDSObjId = dsObjId;
    }

    /**
     * @return The data source object id to filter on if > 0.
     */
    long filteringDataSourceObjId() {
        return this.filteringDSObjId;
    }

    @Override
    public <T> T accept(AutopsyItemVisitor<T> visitor) {
        return visitor.visit(this);
    }

    /**
     * @return The sleuthkit case used.
     */
    public SleuthkitCase getSleuthkitCase() {
        return this.skCase;
    }

    private static final Set<Case.Events> CASE_EVENTS_OF_INTEREST = EnumSet.of(
            Case.Events.DATA_SOURCE_ADDED,
            Case.Events.CURRENT_CASE,
            Case.Events.CONTENT_TAG_ADDED,
            Case.Events.CONTENT_TAG_DELETED,
            Case.Events.BLACKBOARD_ARTIFACT_TAG_ADDED,
            Case.Events.BLACKBOARD_ARTIFACT_TAG_DELETED
    );
    private static final Set<String> CASE_EVENTS_OF_INTEREST_STRS = CASE_EVENTS_OF_INTEREST.stream()
            .map(evt -> evt.name())
            .collect(Collectors.toSet());

    private static final Set<IngestManager.IngestJobEvent> INGEST_JOB_EVENTS_OF_INTEREST = EnumSet.of(IngestManager.IngestJobEvent.COMPLETED, IngestManager.IngestJobEvent.CANCELLED);
    private static final Set<IngestManager.IngestModuleEvent> INGEST_MODULE_EVENTS_OF_INTEREST = EnumSet.of(IngestModuleEvent.CONTENT_CHANGED);

    /**
     * Returns a property change listener listening for possible updates to
     * aggregate score updates for files.
     *
     * @param onRefresh Action on refresh.
     * @param onRemove Action to remove listener (i.e. case close).
     * @return The property change listener.
     */
    private static PropertyChangeListener getPcl(final Runnable onRefresh, final Runnable onRemove) {
        return (PropertyChangeEvent evt) -> {
            String eventType = evt.getPropertyName();
            if (eventType.equals(IngestManager.IngestModuleEvent.CONTENT_CHANGED.toString())) {
                // only refresh if there is a current case.
                try {
                    Case.getCurrentCaseThrows();
                    if (onRefresh != null) {
                        onRefresh.run();
                    }
                } catch (NoCurrentCaseException notUsed) {
                    /**
                     * Case is closed, do nothing.
                     */
                }
            } else if (eventType.equals(Case.Events.CURRENT_CASE.toString())) {
                // case was closed. Remove listeners so that we don't get called with a stale case handle
                if (evt.getNewValue() == null && onRemove != null) {
                    onRemove.run();
                }
            } else if (CASE_EVENTS_OF_INTEREST_STRS.contains(eventType)) {
                // only refresh if there is a current case.
                try {
                    Case.getCurrentCaseThrows();
                    if (onRefresh != null) {
                        onRefresh.run();
                    }
                } catch (NoCurrentCaseException notUsed) {
                    /**
                     * Case is closed, do nothing.
                     */
                }
            }
        };
    }

    /**
     * The sql where statement for the content.
     *
     * @param filter The filter type.
     * @param objIdAlias The alias for the object id of the content. Must be sql
     * safe.
     * @param dsIdAlias The alias for the data source id. Must be sql safe.
     * @param filteringDSObjId The data source object id to filter on if > 0.
     * @return The sql where statement.
     * @throws IllegalArgumentException
     */
    private static String getFilter(ScoreContent.ScoreContentFilter filter, String objIdAlias, String dsIdAlias, long filteringDSObjId) throws IllegalArgumentException {
        String aggregateScoreFilter = getScoreFilter(filter);
        String query = " " + objIdAlias + " IN (SELECT tsk_aggregate_score.obj_id FROM tsk_aggregate_score WHERE " + aggregateScoreFilter + ") ";

        if (filteringDSObjId > 0) {
            query += " AND " + dsIdAlias + " = " + filteringDSObjId;
        }
        return query;
    }

    private static String getScoreFilter(ScoreContentFilter filter) throws IllegalArgumentException {
        switch (filter) {
            case SUS_ITEM_FILTER:
                return " tsk_aggregate_score.significance = " + Significance.LIKELY_NOTABLE.getId()
                        + " AND (tsk_aggregate_score.priority = " + Priority.NORMAL.getId() + " OR tsk_aggregate_score.priority = " + Priority.OVERRIDE.getId() + " )";
            case BAD_ITEM_FILTER:
                return " tsk_aggregate_score.significance = " + Significance.NOTABLE.getId()
                        + " AND (tsk_aggregate_score.priority = " + Priority.NORMAL.getId() + " OR tsk_aggregate_score.priority = " + Priority.OVERRIDE.getId() + " )";
            default:
                throw new IllegalArgumentException(MessageFormat.format("Unsupported filter type to get suspect content: {0}", filter));
        }
    }

    /**
     * Returns a sql where statement for files.
     *
     * @param filter The filter type.
     * @param filteringDSObjId The data source object id to filter on if > 0.
     * @return The sql where statement.
     * @throws IllegalArgumentException
     */
    private static String getFileFilter(ScoreContent.ScoreContentFilter filter, long filteringDsObjId) throws IllegalArgumentException {
        return getFilter(filter, "obj_id", "data_source_obj_id", filteringDsObjId);
    }

    /**
     * Returns a sql where statement for files.
     *
     * @param filter The filter type.
     * @param filteringDSObjId The data source object id to filter on if > 0.
     * @return The sql where statement.
     * @throws IllegalArgumentException
     */
    private static String getDataArtifactFilter(ScoreContent.ScoreContentFilter filter, long filteringDsObjId) throws IllegalArgumentException {
        return getFilter(filter, "artifacts.artifact_obj_id", "artifacts.data_source_obj_id", filteringDsObjId);
    }

    /**
     * Checks for analysis results added to the case that could affect the
     * aggregate score of the file.
     *
     * @param evt The event.
     * @return True if has an analysis result.
     */
    private static boolean isRefreshRequired(PropertyChangeEvent evt) {
        String eventType = evt.getPropertyName();
        if (eventType.equals(IngestManager.IngestModuleEvent.DATA_ADDED.toString())) {
            // check if current case is active before updating
            try {
                Case.getCurrentCaseThrows();
                final ModuleDataEvent event = (ModuleDataEvent) evt.getOldValue();
                if (null != event && Category.ANALYSIS_RESULT.equals(event.getBlackboardArtifactType().getCategory())) {
                    return true;
                }
            } catch (NoCurrentCaseException notUsed) {
                /**
                 * Case is closed, do nothing.
                 */
            }
        }
        return false;
    }

    /**
     * Parent node in views section for content with score.
     */
    public static class ScoreContentsNode extends DisplayableItemNode {

        @NbBundle.Messages("ScoreContent_ScoreContentNode_name=Score")
        private static final String NAME = Bundle.ScoreContent_ScoreContentNode_name();

        ScoreContentsNode(SleuthkitCase skCase, long datasourceObjId) {
            super(Children.create(new ScoreContentsChildren(skCase, datasourceObjId), true), Lookups.singleton(NAME));
            super.setName(NAME);
            super.setDisplayName(NAME);
            this.setIconBaseWithExtension("org/sleuthkit/autopsy/images/red-circle-exclamation.png"); //NON-NLS
        }

        @Override
        public boolean isLeafTypeNode() {
            return false;
        }

        @Override
        public <T> T accept(DisplayableItemNodeVisitor<T> visitor) {
            return visitor.visit(this);
        }

        @Override
        @NbBundle.Messages({
            "ScoreContent_createSheet_name_displayName=Name",
            "ScoreContent_createSheet_name_desc=no description"})
        protected Sheet createSheet() {
            Sheet sheet = super.createSheet();
            Sheet.Set sheetSet = sheet.get(Sheet.PROPERTIES);
            if (sheetSet == null) {
                sheetSet = Sheet.createPropertiesSet();
                sheet.put(sheetSet);
            }

            sheetSet.put(new NodeProperty<>("Name", //NON-NLS
                    Bundle.ScoreContent_createSheet_name_displayName(),
                    Bundle.ScoreContent_createSheet_name_desc(),
                    NAME));
            return sheet;
        }

        @Override
        public String getItemType() {
            return getClass().getName();
        }
    }

    /**
     * Children that display a node for Bad Items and Score Items.
     */
    public static class ScoreContentsChildren extends ChildFactory.Detachable<ScoreContent.ScoreContentFilter> implements RefreshThrottler.Refresher {

        private SleuthkitCase skCase;
        private final long datasourceObjId;

        private final RefreshThrottler refreshThrottler = new RefreshThrottler(this);

        private final PropertyChangeListener pcl = getPcl(
                () -> ScoreContentsChildren.this.refresh(false),
                () -> ScoreContentsChildren.this.removeNotify());

        private final PropertyChangeListener weakPcl = WeakListeners.propertyChange(pcl, null);

        private final Map<ScoreContentFilter, ScoreContentsChildren.ScoreContentNode> typeNodeMap = new HashMap<>();

        public ScoreContentsChildren(SleuthkitCase skCase, long dsObjId) {
            this.skCase = skCase;
            this.datasourceObjId = dsObjId;
        }

        @Override
        protected void addNotify() {
            super.addNotify();
            refreshThrottler.registerForIngestModuleEvents();
            IngestManager.getInstance().addIngestJobEventListener(INGEST_JOB_EVENTS_OF_INTEREST, weakPcl);
            IngestManager.getInstance().addIngestModuleEventListener(INGEST_MODULE_EVENTS_OF_INTEREST, weakPcl);
            Case.addEventTypeSubscriber(CASE_EVENTS_OF_INTEREST, weakPcl);
        }

        @Override
        protected void removeNotify() {
            refreshThrottler.unregisterEventListener();
            IngestManager.getInstance().removeIngestJobEventListener(INGEST_JOB_EVENTS_OF_INTEREST, weakPcl);
            IngestManager.getInstance().removeIngestModuleEventListener(INGEST_MODULE_EVENTS_OF_INTEREST, weakPcl);
            Case.removeEventTypeSubscriber(CASE_EVENTS_OF_INTEREST, weakPcl);
            typeNodeMap.clear();
        }

        @Override
        public void refresh() {
            refresh(false);
        }

        @Override
        public boolean isRefreshRequired(PropertyChangeEvent evt) {
            return ScoreContent.isRefreshRequired(evt);
        }

        @Override
        protected boolean createKeys(List<ScoreContent.ScoreContentFilter> list) {
            list.addAll(Arrays.asList(ScoreContent.ScoreContentFilter.values()));
            typeNodeMap.values().forEach(nd -> nd.updateDisplayName());
            return true;
        }

        @Override
        protected Node createNodeForKey(ScoreContent.ScoreContentFilter key) {
            ScoreContentsChildren.ScoreContentNode nd = new ScoreContentsChildren.ScoreContentNode(skCase, key, datasourceObjId);
            typeNodeMap.put(key, nd);
            return nd;
        }

        /**
         * Parent node showing files matching a score filter.
         */
        public class ScoreContentNode extends DisplayableItemNode {

            private static final Logger logger = Logger.getLogger(ScoreContentNode.class.getName());
            private final ScoreContent.ScoreContentFilter filter;
            private final long datasourceObjId;

            ScoreContentNode(SleuthkitCase skCase, ScoreContent.ScoreContentFilter filter, long dsObjId) {
                super(Children.create(new ScoreContentChildren(filter, skCase, dsObjId), true), Lookups.singleton(filter.getDisplayName()));
                this.filter = filter;
                this.datasourceObjId = dsObjId;
                init();
            }

            private void init() {
                super.setName(filter.getName());

                String tooltip = filter.getDisplayName();
                this.setShortDescription(tooltip);
                switch (this.filter) {
                    case SUS_ITEM_FILTER:
                        this.setIconBaseWithExtension("org/sleuthkit/autopsy/images/yellow-circle-yield.png"); //NON-NLS
                        break;
                    default:
                    case BAD_ITEM_FILTER:
                        this.setIconBaseWithExtension("org/sleuthkit/autopsy/images/red-circle-exclamation.png"); //NON-NLS
                        break;
                }

                updateDisplayName();
            }

            void updateDisplayName() {
                //get count of children without preloading all child nodes
                long count = 0;
                try {
                    count = calculateItems(skCase, filter, datasourceObjId);
                } catch (TskCoreException ex) {
                    logger.log(Level.WARNING, "An error occurred while fetching file counts", ex);
                }
                super.setDisplayName(filter.getDisplayName() + " (" + count + ")");
            }

            /**
             * Get children count without actually loading all nodes
             *
             * @param sleuthkitCase
             * @param filter
             *
             * @return
             */
            private static long calculateItems(SleuthkitCase sleuthkitCase, ScoreContent.ScoreContentFilter filter, long datasourceObjId) throws TskCoreException {
                AtomicLong retVal = new AtomicLong(0L);
                AtomicReference<SQLException> exRef = new AtomicReference(null);

                String query = " COUNT(tsk_aggregate_score.obj_id) AS count FROM tsk_aggregate_score WHERE\n"
                        + getScoreFilter(filter) + "\n"
                        + ((datasourceObjId > 0) ? "AND tsk_aggregate_score.data_source_obj_id = \n" + datasourceObjId : "")
                        + " AND tsk_aggregate_score.obj_id IN\n"
                        + " (SELECT tsk_files.obj_id AS obj_id FROM tsk_files UNION\n"
                        + "     SELECT blackboard_artifacts.artifact_obj_id AS obj_id FROM blackboard_artifacts WHERE blackboard_artifacts.artifact_type_id IN\n"
                        + "         (SELECT artifact_type_id FROM blackboard_artifact_types WHERE category_type = " + Category.DATA_ARTIFACT.getID() + ")) ";
                sleuthkitCase.getCaseDbAccessManager().select(query, (rs) -> {
                    try {
                        if (rs.next()) {
                            retVal.set(rs.getLong("count"));
                        }
                    } catch (SQLException ex) {
                        exRef.set(ex);
                    }
                });

                SQLException sqlEx = exRef.get();
                if (sqlEx != null) {
                    throw new TskCoreException(
                            MessageFormat.format("A sql exception occurred fetching results with query: SELECT {0}", query),
                            sqlEx);
                } else {
                    return retVal.get();
                }
            }

            @Override
            public <T> T accept(DisplayableItemNodeVisitor<T> visitor) {
                return visitor.visit(this);
            }

            @Override
            @NbBundle.Messages({
                "ScoreContent_createSheet_filterType_displayName=Type",
                "ScoreContent_createSheet_filterType_desc=no description"})
            protected Sheet createSheet() {
                Sheet sheet = super.createSheet();
                Sheet.Set sheetSet = sheet.get(Sheet.PROPERTIES);
                if (sheetSet == null) {
                    sheetSet = Sheet.createPropertiesSet();
                    sheet.put(sheetSet);
                }

                sheetSet.put(new NodeProperty<>("Type", //NON_NLS
                        Bundle.ScoreContent_createSheet_filterType_displayName(),
                        Bundle.ScoreContent_createSheet_filterType_desc(),
                        filter.getDisplayName()));

                return sheet;
            }

            @Override
            public boolean isLeafTypeNode() {
                return true;
            }

            @Override
            public String getItemType() {
                return DisplayableItemNode.FILE_PARENT_NODE_KEY;
            }
        }

        /**
         * Children showing files for a score filter.
         */
        static class ScoreContentChildren extends BaseChildFactory<Content> implements RefreshThrottler.Refresher {

            private final RefreshThrottler refreshThrottler = new RefreshThrottler(this);

            private final PropertyChangeListener pcl = getPcl(
                    () -> ScoreContentChildren.this.refresh(false),
                    () -> ScoreContentChildren.this.removeNotify());

            private final PropertyChangeListener weakPcl = WeakListeners.propertyChange(pcl, null);

            private final SleuthkitCase skCase;
            private final ScoreContent.ScoreContentFilter filter;
            private static final Logger logger = Logger.getLogger(ScoreContentChildren.class.getName());

            private final long datasourceObjId;

            ScoreContentChildren(ScoreContent.ScoreContentFilter filter, SleuthkitCase skCase, long datasourceObjId) {
                super(filter.getName(), new ViewsKnownAndSlackFilter<>());
                this.skCase = skCase;
                this.filter = filter;
                this.datasourceObjId = datasourceObjId;
            }

            @Override
            protected void onAdd() {
                refreshThrottler.registerForIngestModuleEvents();
                IngestManager.getInstance().addIngestJobEventListener(INGEST_JOB_EVENTS_OF_INTEREST, weakPcl);
                IngestManager.getInstance().addIngestModuleEventListener(INGEST_MODULE_EVENTS_OF_INTEREST, weakPcl);
                Case.addEventTypeSubscriber(CASE_EVENTS_OF_INTEREST, weakPcl);
            }

            @Override
            protected void onRemove() {
                refreshThrottler.unregisterEventListener();
                IngestManager.getInstance().removeIngestJobEventListener(INGEST_JOB_EVENTS_OF_INTEREST, weakPcl);
                IngestManager.getInstance().removeIngestModuleEventListener(INGEST_MODULE_EVENTS_OF_INTEREST, weakPcl);
                Case.removeEventTypeSubscriber(CASE_EVENTS_OF_INTEREST, weakPcl);
            }

            @Override
            public void refresh() {
                refresh(false);
            }

            @Override
            public boolean isRefreshRequired(PropertyChangeEvent evt) {
                return ScoreContent.isRefreshRequired(evt);
            }

            private List<Content> runFsQuery() {
                List<Content> ret = new ArrayList<>();

                String fileFilter = null;
                String dataArtifactFilter = null;
                try {
                    fileFilter = getFileFilter(filter, datasourceObjId);
                    dataArtifactFilter = getDataArtifactFilter(filter, datasourceObjId);
                    ret.addAll(skCase.findAllFilesWhere(fileFilter));
                    ret.addAll(skCase.getBlackboard().getDataArtifactsWhere(dataArtifactFilter));
                } catch (TskCoreException | IllegalArgumentException e) {
                    logger.log(Level.SEVERE, MessageFormat.format(
                            "Error getting files for the deleted content view using file filter: {0} data artifact filter: {1}",
                            StringUtils.defaultString(fileFilter, "<null>"),
                            StringUtils.defaultString(dataArtifactFilter, "<null>")), e); //NON-NLS
                }

                return ret;

            }

            @Override
            protected List<Content> makeKeys() {
                return runFsQuery();
            }

            @Override
            protected Node createNodeForKey(Content key) {
                return key.accept(new ContentVisitor.Default<AbstractNode>() {
                    public FileNode visit(AbstractFile f) {
                        return new ScoreFileNode(f, false);
                    }

                    public FileNode visit(FsContent f) {
                        return new ScoreFileNode(f, false);
                    }

                    @Override
                    public FileNode visit(LayoutFile f) {
                        return new ScoreFileNode(f, false);
                    }

                    @Override
                    public FileNode visit(File f) {
                        return new ScoreFileNode(f, false);
                    }

                    @Override
                    public FileNode visit(Directory f) {
                        return new ScoreFileNode(f, false);
                    }

                    @Override
                    public FileNode visit(VirtualDirectory f) {
                        return new ScoreFileNode(f, false);
                    }

                    @Override
                    public AbstractNode visit(SlackFile sf) {
                        return new ScoreFileNode(sf, false);
                    }

                    @Override
                    public AbstractNode visit(LocalFile lf) {
                        return new ScoreFileNode(lf, false);
                    }

                    @Override
                    public AbstractNode visit(DerivedFile df) {
                        return new ScoreFileNode(df, false);
                    }

                    @Override
                    public AbstractNode visit(BlackboardArtifact ba) {
                        return new ScoreArtifactNode(ba);
                    }

                    @Override
                    protected AbstractNode defaultVisit(Content di) {
                        if (di instanceof AbstractFile) {
                            return visit((AbstractFile) di);
                        } else {
                            throw new UnsupportedOperationException("Not supported for this type of Displayable Item: " + di.toString());
                        }
                    }
                });
            }
        }
    }

    private static final String SOURCE_PROP = "Source";
    private static final String TYPE_PROP = "Type";
    private static final String PATH_PROP = "Path";
    private static final String DATE_PROP = "Created Date";

    private static Sheet createScoreSheet(String type, String path, Long time) {
        Sheet sheet = new Sheet();
        Sheet.Set sheetSet = Sheet.createPropertiesSet();
        sheet.put(sheetSet);

        List<NodeProperty<?>> properties = new ArrayList<>();
        properties.add(new NodeProperty<>(
                SOURCE_PROP,
                SOURCE_PROP,
                NO_DESCR,
                StringUtils.defaultString(path)));

        properties.add(new NodeProperty<>(
                TYPE_PROP,
                TYPE_PROP,
                NO_DESCR,
                type));

        if (StringUtils.isNotBlank(path)) {
            properties.add(new NodeProperty<>(
                    PATH_PROP,
                    PATH_PROP,
                    NO_DESCR,
                    path));
        }

        if (time != null && time > 0) {
            properties.add(new NodeProperty<>(
                    DATE_PROP,
                    DATE_PROP,
                    NO_DESCR,
                    TimeZoneUtils.getFormattedTime(time)));
        }

        properties.forEach((property) -> {
            sheetSet.put(property);
        });

        return sheet;
    }

    public static class ScoreArtifactNode extends BlackboardArtifactNode {

        private static final Logger logger = Logger.getLogger(ScoreArtifactNode.class.getName());

        private static final List<BlackboardAttribute.Type> TIME_ATTRS = Arrays.asList(
                BlackboardAttribute.Type.TSK_DATETIME,
                BlackboardAttribute.Type.TSK_DATETIME_ACCESSED,
                BlackboardAttribute.Type.TSK_DATETIME_RCVD,
                BlackboardAttribute.Type.TSK_DATETIME_SENT,
                BlackboardAttribute.Type.TSK_DATETIME_CREATED,
                BlackboardAttribute.Type.TSK_DATETIME_MODIFIED,
                BlackboardAttribute.Type.TSK_DATETIME_START,
                BlackboardAttribute.Type.TSK_DATETIME_END,
                BlackboardAttribute.Type.TSK_DATETIME_DELETED,
                BlackboardAttribute.Type.TSK_DATETIME_PASSWORD_RESET,
                BlackboardAttribute.Type.TSK_DATETIME_PASSWORD_FAIL
        );

        private static final Map<Integer, Integer> TIME_ATTR_IMPORTANCE = IntStream.range(0, TIME_ATTRS.size())
                .mapToObj(idx -> Pair.of(TIME_ATTRS.get(idx).getTypeID(), idx))
                .collect(Collectors.toMap(Entry::getKey, Entry::getValue, (v1, v2) -> v1));

        public ScoreArtifactNode(BlackboardArtifact artifact) {
            super(artifact);
        }

        private Long getTime(BlackboardArtifact artifact) {
            try {
                BlackboardAttribute timeAttr = artifact.getAttributes().stream()
                        .filter((attr) -> TIME_ATTR_IMPORTANCE.keySet().contains(attr.getAttributeType().getTypeID()))
                        .sorted(Comparator.comparing(attr -> TIME_ATTR_IMPORTANCE.get(attr.getAttributeType().getTypeID())))
                        .findFirst()
                        .orElse(null);

                if (timeAttr != null) {
                    return timeAttr.getValueLong();
                } else {
                    return (artifact.getParent() instanceof AbstractFile) ? ((AbstractFile) artifact.getParent()).getCtime() : null;
                }
            } catch (TskCoreException ex) {
                logger.log(Level.WARNING, "An exception occurred while fetching time for artifact", ex);
                return null;
            }
        }

        @Override
        protected synchronized Sheet createSheet() {
            try {
                return createScoreSheet(
                        this.content.getType().getDisplayName(),
                        this.content.getUniquePath(),
                        getTime(this.content)
                );
            } catch (TskCoreException ex) {
                logger.log(Level.WARNING, "An error occurred while fetching sheet data for score artifact.", ex);
                return new Sheet();
            }
        }
    }

    @Messages("ScoreContent_ScoreFileNode_type=File")
    public static class ScoreFileNode extends FileNode {

        private static final Logger logger = Logger.getLogger(ScoreFileNode.class.getName());

        public ScoreFileNode(AbstractFile af, boolean directoryBrowseMode) {
            super(af, directoryBrowseMode);
        }

        @Override
        protected synchronized Sheet createSheet() {
            try {
                return createScoreSheet(
                        Bundle.ScoreContent_ScoreFileNode_type(),
                        this.content.getUniquePath(),
                        this.content.getCtime()
                );
            } catch (TskCoreException ex) {
                logger.log(Level.WARNING, "An error occurred while fetching sheet data for score file.", ex);
                return new Sheet();
            }
        }
    }
}
