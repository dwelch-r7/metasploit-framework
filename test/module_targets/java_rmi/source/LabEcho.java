import java.rmi.Remote;
import java.rmi.RemoteException;

public interface LabEcho extends Remote {
  String ping(String value) throws RemoteException;
  String readProof(String token) throws Exception;
  boolean removeProof(String token) throws Exception;
  String loaderPolicy() throws RemoteException;
}
