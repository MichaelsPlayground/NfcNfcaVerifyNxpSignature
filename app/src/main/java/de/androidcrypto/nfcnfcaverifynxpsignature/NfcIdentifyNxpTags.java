package de.androidcrypto.nfcnfcaverifynxpsignature;

import android.nfc.tech.NfcA;

import java.io.IOException;
import java.util.Arrays;

/**
 * This class trys to identify a NFC tag produced by NXP using the getVersion command
 */


public class NfcIdentifyNxpTags {

    private static String identifiedNxpTagType = ""; // NTAG213, NTAG215 or NTAG216
    private static int identifiedNxpTagPages = 0; // NTAG 213 = 36, 215 = 126, 216 = 222 pages
    private static int identifiedNxpTagMemoryBytes = 0; // NTAG 213 = 144, 215 = 504, 216 = 888 bytes
    private static byte[] identifiedNxpTagId = new byte[0];

    // data show here are from NXP NTAG21x data sheet
    private static byte[] ntag213VersionData = new byte[]{
            (byte) 0x00, // fixed header
            (byte) 0x04, // vendor ID, 04h = NXP
            (byte) 0x04, // product type = NTAG
            (byte) 0x02, // product subtype = 50 pF
            (byte) 0x01, // major product version 1
            (byte) 0x00, // minor product version V0
            (byte) 0x0F, // storage size = 144 bytes
            (byte) 0x03  // protocol type = ISO/IEC 14443-3 compliant
    };
    private static byte[] ntag215VersionData = new byte[]{
            (byte) 0x00, // fixed header
            (byte) 0x04, // vendor ID, 04h = NXP
            (byte) 0x04, // product type = NTAG
            (byte) 0x02, // product subtype = 50 pF
            (byte) 0x01, // major product version 1
            (byte) 0x00, // minor product version V0
            (byte) 0x11, // storage size = 504 bytes
            (byte) 0x03  // protocol type = ISO/IEC 14443-3 compliant
    };
    private static byte[] ntag216VersionData = new byte[]{
            (byte) 0x00, // fixed header
            (byte) 0x04, // vendor ID, 04h = NXP
            (byte) 0x04, // product type = NTAG
            (byte) 0x02, // product subtype = 50 pF
            (byte) 0x01, // major product version 1
            (byte) 0x00, // minor product version V0
            (byte) 0x13, // storage size = 888 bytes
            (byte) 0x03  // protocol type = ISO/IEC 14443-3 compliant
    };
    // data show here are from NXP Ultralight EV1 data sheet
    private static byte[] ultralightEv1_M0UL11VersionData = new byte[]{
            (byte) 0x00, // fixed header
            (byte) 0x04, // vendor ID, 04h = NXP
            (byte) 0x03, // product type = MIFARE Ultralight
            (byte) 0x01, // product subtype = 17 pF
            (byte) 0x01, // major product version 1
            (byte) 0x00, // minor product version V0
            (byte) 0x0B, // storage size = 888 bytes
            (byte) 0x03  // protocol type = ISO/IEC 14443-3 compliant
    };
    private static byte[] ultralightEv1_M0ULH11VersionData = new byte[]{
            (byte) 0x00, // fixed header
            (byte) 0x04, // vendor ID, 04h = NXP
            (byte) 0x03, // product type = MIFARE Ultralight
            (byte) 0x02, // product subtype = 50 pF
            (byte) 0x01, // major product version 1
            (byte) 0x00, // minor product version V0
            (byte) 0x0B, // storage size = 48 bytes
            (byte) 0x03  // protocol type = ISO/IEC 14443-3 compliant
    };
    private static byte[] ultralightEv1_M0UL21VersionData = new byte[]{
            (byte) 0x00, // fixed header
            (byte) 0x04, // vendor ID, 04h = NXP
            (byte) 0x03, // product type = MIFARE Ultralight
            (byte) 0x01, // product subtype = 17 pF
            (byte) 0x01, // major product version 1
            (byte) 0x00, // minor product version V0
            (byte) 0x0E, // storage size = 144 bytes
            (byte) 0x03  // protocol type = ISO/IEC 14443-3 compliant
    };
    private static byte[] ultralightEv1_M0ULH21VersionData = new byte[]{
            (byte) 0x00, // fixed header
            (byte) 0x04, // vendor ID, 04h = NXP
            (byte) 0x03, // product type = MIFARE Ultralight
            (byte) 0x02, // product subtype = 50 pF
            (byte) 0x01, // major product version 1
            (byte) 0x00, // minor product version V0
            (byte) 0x0E, // storage size = 144 bytes
            (byte) 0x03  // protocol type = ISO/IEC 14443-3 compliant
    };
    // data show here are from NXP Mifare Classic EV1 data sheet
    // https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf
    // NOTE: THIS IS NOT WORKING !!!!
    private static byte[] mifareClassicEv1_M0UL11VersionData = new byte[]{
            (byte) 0x00, // fixed header
            (byte) 0x04, // vendor ID, 04h = NXP
            (byte) 0x03, // product type = MIFARE Ultralight
            (byte) 0x01, // product subtype = 17 pF
            (byte) 0x01, // major product version 1
            (byte) 0x00, // minor product version V0
            (byte) 0x0B, // storage size = 888 bytes
            (byte) 0x03  // protocol type = ISO/IEC 14443-3 compliant
    };


    // returns 213/215/216 if tag is found or 0 when not detected in case of NTAG21x
    // returns ultralightev1s or ultralightev1l if tag is found or 0 when not detected in case of Ultralight EV1

    public static String checkNxpTagType(NfcA nfca, byte[] ntagId) {
        clearInternalData();
        String returnCode = "0";
        identifiedNxpTagId = ntagId;
        byte[] response;
        // first we are checking that the tag is produced by NXP
        // Get Page 00h
        // reads 16 bytes = 4 pages in one run
        try {
            response = nfca.transceive(new byte[]{
                    (byte) 0x30, // READ
                    (byte) 0x00  // page address
            });
            System.out.println("check read response1: " + Utils.bytesToHex(response));
            // only check for byte 00 - 03h means NXP...
            byte[] uid0 = Arrays.copyOfRange(response, 0, 1);
            if (!Arrays.equals(uid0, new byte[]{(byte) 0x04})) {
                return returnCode; // not produced by NXP
            }
            // get version
            response = nfca.transceive(new byte[] {
                    (byte) 0x60 // GET VERSION
            });
            System.out.println("check read version response: " + Utils.bytesToHex(response));
            if (Arrays.equals(response, ntag213VersionData)) {
                returnCode = "213";
                identifiedNxpTagType = "NTAG213";
                identifiedNxpTagPages = 36;
                identifiedNxpTagMemoryBytes = 144;
            }
            if (Arrays.equals(response, ntag215VersionData)) {
                returnCode = "215";
                identifiedNxpTagType = "NTAG215";
                identifiedNxpTagPages = 126;
                identifiedNxpTagMemoryBytes = 504;
            }
            if (Arrays.equals(response, ntag216VersionData)) {
                returnCode = "216";
                identifiedNxpTagType = "NTAG216";
                identifiedNxpTagPages = 222;
                identifiedNxpTagMemoryBytes = 888;
            }
            if (Arrays.equals(response, ultralightEv1_M0UL11VersionData)) {
                returnCode = "ultralightev1s";
                identifiedNxpTagType = "Ultralight EV1 M0UL11";
                identifiedNxpTagPages = 12;
                identifiedNxpTagMemoryBytes = 48;
            }
            if (Arrays.equals(response, ultralightEv1_M0ULH11VersionData)) {
                returnCode = "ultralightev1s";
                identifiedNxpTagType = "Ultralight EV1 M0UL11H";
                identifiedNxpTagPages = 12;
                identifiedNxpTagMemoryBytes = 48;
            }
            if (Arrays.equals(response, ultralightEv1_M0UL21VersionData)) {
                returnCode = "ultralightev1l";
                identifiedNxpTagType = "Ultralight EV1 M0UL21";
                identifiedNxpTagPages = 36;
                identifiedNxpTagMemoryBytes = 144;
            }
            if (Arrays.equals(response, ultralightEv1_M0ULH21VersionData)) {
                returnCode = "ultralightev1l";
                identifiedNxpTagType = "Ultralight EV1 M0ULH21";
                identifiedNxpTagPages = 36;
                identifiedNxpTagMemoryBytes = 144;
            }
        } catch (IOException e) {
            System.out.println("read version failed - no NTAG21x or Mifare Ultralight EV1 card");
            // try another way for Mifare Classic EV1
            returnCode = checkNxpMifareClassicEv1TagType(nfca, ntagId);
            identifiedNxpTagType = "Classic EV1";
            System.out.println("newReturnCode: " + returnCode);
            e.printStackTrace();

        }
        return returnCode;
    }

    private static String checkNxpMifareClassicEv1TagType(NfcA nfca, byte[] ntagId) {
        byte[] atqa = nfca.getAtqa();
        short sak = nfca.getSak();
        System.out.println("atqa: " + Utils.bytesToHex(atqa));
        System.out.println("sak: " + sak);
        if (sak == 8) {
            return "mifareclassicev1";
        } else {
            return "0";
        }
    }

    public static String getidentifiedNxpTagType() {
        return identifiedNxpTagType;
    }

    public static int getidentifiedNxpTagPages() {
        return identifiedNxpTagPages;
    }

    public static int getidentifiedNxpTagMemoryBytes() { return identifiedNxpTagMemoryBytes; }

    public static byte[] getidentifiedNxpTagId() { return identifiedNxpTagId; }

    public static void clearInternalData() {
        identifiedNxpTagType = "";
        identifiedNxpTagPages = 0;
        identifiedNxpTagMemoryBytes = 0;
        identifiedNxpTagId = new byte[0];
    }

}
