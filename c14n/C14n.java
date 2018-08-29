import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class C14n {
    private static Map<Long, byte[]> metadataKeys = new HashMap<Long, byte[]>() {{
        put(0L, new byte[]{1, 2, 3});
        put(1L, new byte[]{1, 2, 3});
    }};

    private static Map<String, byte[]> recipients = new HashMap<String, byte[]>() {{
        put("alice", new byte[]{1, 2, 3});
        put("bob", new byte[]{1, 2, 3});
        put("charlie", new byte[]{1, 2, 3});
    }};

    private static Map<String, Long> files = new HashMap<String, Long>() {{
        put("file1", 1L);
        put("file2", 0L);
        put("file3", 0L);
    }};

    private static void writeInt32(ByteArrayOutputStream stream, int n) {
        stream.write((n & 0xFF000000) >> 24);
        stream.write((n & 0x00FF0000) >> 16);
        stream.write((n & 0x0000FF00) >> 8);
        stream.write(n & 0x000000FF);
    }

    private static void writeInt64(ByteArrayOutputStream stream, long n) {
        int offset = 64;
        long mask = 0xFF00000000000000L;
        while (offset != 0) {
            offset -= 8;
            stream.write((byte) ((n & mask) >> offset));
            mask >>= 8;
        }
    }

    public byte[] c14n(int protocolVersion, Map<Long, byte[]> metadataKeys, Map<String, byte[]> recipients, Map<String, Long> files) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();

        Long[] metadataKeysIndices = metadataKeys.keySet().toArray(new Long[0]);
        String[] recipientNames = recipients.keySet().toArray(new String[0]);
        String[] fileIds = files.keySet().toArray(new String[0]);

        Arrays.sort(metadataKeysIndices);
        Arrays.sort(recipientNames);
        Arrays.sort(fileIds);

        writeInt32(byteStream, protocolVersion);

        for (Long index : metadataKeysIndices) {
            writeInt64(byteStream, index);
            byteStream.write(metadataKeys.get(index));
        }

        for (String name : recipientNames) {
            byteStream.write(name.getBytes("utf-8"));
            byteStream.write(recipients.get(name));
        }

        for (String fileId : fileIds) {
            byteStream.write(fileId.getBytes("utf-8"));
            writeInt64(byteStream, files.get(fileId));
        }

        return byteStream.toByteArray();
    }

    public static void main(String[] args) throws IOException {
        System.out.println(Arrays.toString(new C14n().c14n(1, metadataKeys, recipients, files)));
    }
}
