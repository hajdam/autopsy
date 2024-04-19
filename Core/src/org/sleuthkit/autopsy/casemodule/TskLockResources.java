/*
 * Autopsy Forensic Browser
 *
 * Copyright 2024 Basis Technology Corp.
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
package org.sleuthkit.autopsy.casemodule;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import org.apache.commons.lang3.StringUtils;

/**
 * The resources associated with the file lock for the TSK database.
 */
class TskLockResources implements AutoCloseable {

    private static final String LOCK_FILE_NAME = "lock";

    private File lockFile = null;
    private RandomAccessFile lockFileRaf = null;
    private FileChannel lockFileChannel = null;
    private FileLock lockFileLock = null;

    /**
     * Constructor.
     *
     * @param lockFile The lock file File reference.
     * @param lockFileRef The lock file random access file reference.
     * @param lockFileChannel The lock file file channel.
     * @param lockFileLock The lock file file lock.
     */
    TskLockResources(File lockFile, RandomAccessFile lockFileRaf, FileChannel lockFileChannel, FileLock lockFileLock) {
        this.lockFile = lockFile;
        this.lockFileRaf = lockFileRaf;
        this.lockFileChannel = lockFileChannel;
        this.lockFileLock = lockFileLock;
    }

    /**
     * Try to acquire a lock to the lock file in the case directory.
     *
     * @param caseDir The case directory that the autopsy.db is in.
     * @return The lock file resources to be closed.
     * @throws IllegalAccessException
     * @throws IOException
     */
    static TskLockResources tryAcquireFileLock(String caseDir, String applicationName) throws ConcurrentDbAccessException, IOException, OverlappingFileLockException {
        // get the lock file path
        File lockFile = new File(caseDir, LOCK_FILE_NAME);
        // make directories leading up to that
        lockFile.getParentFile().mkdirs();

        // if the lock file exists
        if (lockFile.isFile() && !lockFile.canWrite()) {
            // get the random access file as read only
            RandomAccessFile lockFileRaf = new RandomAccessFile(lockFile, "r");
            throw ConcurrentDbAccessException.createForFile(lockFile.getAbsolutePath(), lockFileRaf);
        } else {
            RandomAccessFile lockFileRaf = new RandomAccessFile(lockFile, "rw");
            FileChannel lockFileChannel = lockFileRaf.getChannel();
            FileLock lockFileLock = lockFileChannel == null
                    ? null
                    : lockFileChannel.tryLock(1024L, 1L, false);

            if (lockFileLock != null) {
                lockFileRaf.setLength(0);
                lockFileRaf.writeChars(applicationName);
                return new TskLockResources(lockFile, lockFileRaf, lockFileChannel, lockFileLock);
            } else {
                throw ConcurrentDbAccessException.createForFile(lockFile.getAbsolutePath(), lockFileRaf);
            }
        }
    }

    @Override
    public void close() throws Exception {
        // close lock file resources in reverse acquisition order
        if (this.lockFileLock != null) {
            this.lockFileLock.close();
            this.lockFileLock = null;
        }

        if (this.lockFileChannel != null) {
            this.lockFileChannel.close();
            this.lockFileChannel = null;
        }

        if (this.lockFileRaf != null) {
            this.lockFileRaf.close();
            this.lockFileRaf = null;
        }

        if (this.lockFile != null) {
            this.lockFile.delete();
            this.lockFile = null;
        }
    }

    /**
     * An exception thrown if the database is currently in use.
     */
    static class ConcurrentDbAccessException extends Exception {

        private final String conflictingApplicationName;

        /**
         * Creates a ConcurrentDbAccessException from the lock file path and the
         * random access file of that path whose contents are the application
         * name.
         *
         * @param lockFilePath The lock file path.
         * @param lockFileRaf The lock file random access file.
         * @return The exception
         * @throws IOException
         */
        static ConcurrentDbAccessException createForFile(String lockFilePath, RandomAccessFile lockFileRaf) throws IOException {
            StringBuffer buffer = new StringBuffer();
            while (lockFileRaf.getFilePointer() < lockFileRaf.length()) {
                buffer.append(lockFileRaf.readLine() + System.lineSeparator());
            }
            String conflictingApplication = buffer.toString().trim();
            String message = "Unable to acquire lock on " + lockFilePath + "." + (StringUtils.isNotBlank(conflictingApplication) ? ("  Database is already open in " + conflictingApplication + ".") : "");
            return new ConcurrentDbAccessException(message, conflictingApplication);
        }

        /**
         * Constructor.
         *
         * @param message The exception message.
         * @param conflictingApplicationName The conflicting application name
         * (or null if unknown).
         */
        ConcurrentDbAccessException(String message, String conflictingApplicationName) {
            super(message);
            this.conflictingApplicationName = conflictingApplicationName;
        }

        /**
         * @return The conflicting application name (or null if unknown).
         */
        public String getConflictingApplicationName() {
            return conflictingApplicationName;
        }
    }
}
