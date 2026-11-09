import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
public class UtfReference {
  static byte[] encoded(String value) throws Exception {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    new DataOutputStream(buffer).writeUTF(value);
    return buffer.toByteArray();
  }
  static void frame(DataOutputStream out, int op, byte[] data) throws Exception {
    out.writeInt(data.length); out.writeByte(op); out.write(data);
  }
  static byte[] request(String path, boolean padded, String charset) throws Exception {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(buffer);
    frame(out, 0, encoded("help"));
    if (padded) frame(out, 0, encoded("1"));
    frame(out, 0, encoded("@"+path));
    frame(out, 2, encoded(charset)); frame(out, 1, encoded("en_US"));
    frame(out, 3, new byte[0]); return buffer.toByteArray();
  }
  public static void main(String[] arguments) throws Exception {
    String[][] values = {
      {"help", "help"}, {"locale", "en_US"}, {"encoding", "UTF-8"},
      {"alternate_encoding", "ISO-8859-1"},
      {"unicode_path", "@/opt/module-target/café.txt"},
      {"long_path", "@/opt/module-target/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/proof.txt"},
      {"nul_supplementary", "A" + new String(new char[]{0}) + new String(Character.toChars(0x1f600))}
    };
    for (String[] value : values) System.out.println(value[0]+" "+HexFormat.of().formatHex(encoded(value[1])));
    System.out.println("request_default "+HexFormat.of().formatHex(request("/opt/module-target/two.txt", false, "UTF-8")));
    System.out.println("request_padded "+HexFormat.of().formatHex(request("/opt/module-target/one.txt", true, "UTF-8")));
    System.out.println("request_long "+HexFormat.of().formatHex(request("/opt/module-target/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/proof.txt", false, "UTF-8")));
    System.out.println("request_unicode "+HexFormat.of().formatHex(request("/opt/module-target/café.txt", false, "UTF-8")));
    System.out.println("request_alternate_encoding "+HexFormat.of().formatHex(request("/opt/module-target/two.txt", false, "ISO-8859-1")));
    byte[] maximum = encoded("a".repeat(65535));
    System.out.println("maximum_sha256 "+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(maximum)));
    try { encoded("a".repeat(65536)); throw new AssertionError("Oversized field accepted"); }
    catch (UTFDataFormatException expected) { System.out.println("oversized "+expected.getClass().getName()); }
  }
}
