package com.example.regression;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Java zip-slip case. No TigerGate catalog rule targets this shape; recorded as a known coverage gap. */
public class ZipImporter {
    public void unpack(InputStream in, File dest) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File out = new File(dest, entry.getName()); // JAVA-ZIP-GAP-001
                try (FileOutputStream fos = new FileOutputStream(out)) {
                    zis.transferTo(fos);
                }
            }
        }
    }
}
