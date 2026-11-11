import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public final class LabEchoImpl extends UnicastRemoteObject implements LabEcho {
  private static final long serialVersionUID = 1L;
  public LabEchoImpl() throws RemoteException { super(LabConfig.ECHO); }
  public String ping(String value) { return "module-target-echo:" + value; }
  public String readProof(String token) throws Exception { return new LabState().readProof(token); }
  public boolean removeProof(String token) throws Exception { return new LabState().removeProof(token); }
  public String loaderPolicy() { return new LabState().getLoaderPolicy(); }
}
