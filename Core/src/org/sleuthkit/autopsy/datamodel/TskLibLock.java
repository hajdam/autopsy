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
package org.sleuthkit.autopsy.datamodel;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.logging.Level;

/**
 * Creates a file lock at the old location (Autopsy LTE 4.21.0) of TSK
 * libraries, and does so in such a way that newer versions can determine that
 * it is a new application holding the lock.
 */
class TskLibLock implements AutoCloseable {

    private static final String DLL_EXT = "dll";
    private static final String DYLIB_EXT = "dylib";
    private static final String SO_EXT = "so";

    private static final String LIBTSK_JNI_LIB = "libtsk_jni";

    private static final String LIB_FILE_LOCK_TEXT = "lib_lock";

    private static final String TMP_DIR_KEY = "java.io.tmpdir";
    private static final String USER_NAME_KEY = "user.name";

    private static final byte[] UTF8_BOM = {(byte) 0XEF, (byte) 0xBB, (byte) 0XBF};

    private static TskLibLock libLock = null;

    /**
     * Attempts to acquire a file lock on the libtsk_jni library at the old
     * location if there currently is no lock.
     *
     * @return The result of attempting to obtain the lock including the result
     * type (lock held by new application, lock held by old application, lock
     * acquired) and any resources if the lock is acquired.
     * @throws IOException
     */
    static TskLibLock acquireLibLock() {
        if (libLock == null) {
            libLock = getLibLock();
        }
        return libLock;
    }

    /**
     * Removes any library file lock present.
     *
     * @throws Exception If there is an error closing the lock resources.
     */
    static void removeLibLock() throws Exception {
        if (libLock != null) {
            libLock.close();
        }
    }

    /**
     * Gets the lib lock for the libtsk_jni library at the old location.
     *
     * @return The result of attempting to obtain the lock including the result
     * type (lock held by new application, lock held by old application, lock
     * acquired) and any resources if the lock is acquired.
     * @throws IOException
     */
    private static TskLibLock getLibLock() {
        // TODO error handling cleanup

        String libExt = getLibExtension();
        File libTskJniFile = Paths.get(
                System.getProperty(TMP_DIR_KEY, ""),
                MessageFormat.format("{0}_{1}.{2}",
                        LIBTSK_JNI_LIB,
                        System.getProperty(USER_NAME_KEY, ""),
                        libExt)).toFile();

        // if the lock file exists
        if (libTskJniFile.isFile() && !libTskJniFile.canWrite()) {
            // get the random access file as read only
            try (RandomAccessFile lockFileRaf = new RandomAccessFile(libTskJniFile, "r")) {
                LockState lockState = isNewLock(lockFileRaf)
                        ? LockState.HELD_BY_NEW
                        : LockState.HELD_BY_OLD;

                return new TskLibLock(lockState, libTskJniFile, lockFileRaf, null, null);
            } catch (IOException ex) {
                // if there is an error getting read only access, then it is the old application dll
                java.util.logging.Logger.getLogger(TskLibLock.class.getCanonicalName()).log(Level.WARNING, "An error occurred while acquiring the TSK lib lock", ex);
                return new TskLibLock(LockState.HELD_BY_OLD, libTskJniFile, null, null, null);
            }
        } else {
            // make directories leading up to that
            libTskJniFile.getParentFile().mkdirs();

            // get file access to the file
            RandomAccessFile lockFileRaf = null;
            FileChannel lockFileChannel = null;
            FileLock lockFileLock = null;
            try {
                lockFileRaf = new RandomAccessFile(libTskJniFile, "rw");
                lockFileChannel = lockFileRaf.getChannel();
                lockFileLock = lockFileChannel == null
                        ? null
                        : lockFileChannel.tryLock(1024L, 1L, false);

                if (lockFileLock != null) {
                    lockFileRaf.setLength(0);
                    lockFileRaf.write(UTF8_BOM);
                    lockFileRaf.writeChars(LIB_FILE_LOCK_TEXT);

                    return new TskLibLock(LockState.ACQUIRED, libTskJniFile, lockFileRaf, lockFileChannel, lockFileLock);
                } else {
                    LockState lockState = isNewLock(lockFileRaf)
                            ? LockState.HELD_BY_NEW
                            : LockState.HELD_BY_OLD;

                    return new TskLibLock(lockState, libTskJniFile, lockFileRaf, lockFileChannel, null);
                }
            } catch (IOException ex) {
                // if there is an error getting read only access, then it is the old application dll
                java.util.logging.Logger.getLogger(TskLibLock.class.getCanonicalName()).log(Level.WARNING, "An error occurred while acquiring the TSK lib lock", ex);
                return new TskLibLock(LockState.HELD_BY_OLD, libTskJniFile, lockFileRaf, lockFileChannel, lockFileLock);
            }
        }
    }

    /**
     * Returns true if the file is locked by a newer application (Autopsy GT
     * 4.21.0).
     *
     * @param libRaf The random access file.
     * @return True if lock held by a newer application.
     * @throws IOException
     */
    private static boolean isNewLock(RandomAccessFile libRaf) throws IOException {
        libRaf.seek(0);
        byte[] startFileArr = new byte[UTF8_BOM.length];
        int read = libRaf.read(startFileArr);
        return read == startFileArr.length && Arrays.equals(UTF8_BOM, startFileArr);

    }

    private File libTskJniFile;
    private RandomAccessFile lockFileRaf;
    private FileChannel lockFileChannel;
    private FileLock lockFileLock;
    private LockState lockState;

    /**
     * Constructor
     *
     * @param lockState The lock state.
     * @param lockFile The lock file or null.
     * @param lockFileRaf The lock file random access file or null.
     * @param lockFileChannel The lock file channel or null.
     * @param lockFileLock The lock file lock or null.
     */
    private TskLibLock(
            LockState lockState,
            File lockFile,
            RandomAccessFile lockFileRaf,
            FileChannel lockFileChannel,
            FileLock lockFileLock) {

        this.libTskJniFile = lockFile;
        this.lockFileRaf = lockFileRaf;
        this.lockFileChannel = lockFileChannel;
        this.lockFileLock = lockFileLock;
        this.lockState = lockState;
    }

    /**
     * @return The lock state result of attempting to lock the file.
     */
    LockState getLockState() {
        return lockState;
    }

    /**
     * @return The file path for the lib tsk jni file.
     */
    File getLibTskJniFile() {
        return libTskJniFile;
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

        if (this.libTskJniFile != null) {
            this.libTskJniFile.delete();
            this.libTskJniFile = null;
        }
    }

    /**
     * @return The library extension based on the operating system.
     */
    private static String getLibExtension() {
        if (isWindows()) {
            return DLL_EXT;
        } else if (isMac()) {
            return DYLIB_EXT;
        } else {
            return SO_EXT;
        }
    }

    /**
     * Is the platform Windows?
     *
     * @return
     */
    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("windows");
    }

    /**
     * Is the platform Mac?
     *
     * @return
     */
    private static boolean isMac() {
        return System.getProperty("os.name", "").toLowerCase().contains("mac");
    }

    /**
     * Is the platform Linux?
     *
     * @return
     */
    private static boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase().contains("linux");
    }

    /**
     * The result of attempting to lock the libtsk_jni lib file.
     */
    enum LockState {
        /**
         * If a lock on the library is held by a version of Autopsy LTE 4.21.0
         */
        HELD_BY_OLD,
        /**
         * If a lock on the library is held by a version of Autopsy GT 4.21.0
         */
        HELD_BY_NEW,
        /**
         * If the lock has been acquired.
         */
        ACQUIRED
    }
}
