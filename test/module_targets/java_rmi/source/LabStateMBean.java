public interface LabStateMBean {
  String getRole();
  String getLoaderPolicy();
  String[] getProofs() throws Exception;
  String readProof(String token) throws Exception;
  boolean removeProof(String token) throws Exception;
}
