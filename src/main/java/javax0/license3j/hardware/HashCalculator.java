package javax0.license3j.hardware;


import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Comparator;
import java.util.List;

/**
 * Calculator to calculate a more or less unique code for the actual machine. The calculation uses the
 * network cards, host name and architecture of the machine.
 * <p>
 * This class is used by the {@link UUIDCalculator}. You, using License3j as a library, do not call methods in
 * this class directly.
 */
class HashCalculator {
    private final Network.Interface.Selector selector;

    HashCalculator(Network.Interface.Selector selector) {
        this.selector = selector;
    }

    private void updateWithNetworkData(final MessageDigest md5,
                                       final List<Network.Interface.Data> interfaces) {
        for (final Network.Interface.Data ni : interfaces) {
            md5.update(ni.name.getBytes(StandardCharsets.UTF_8));
            if (ni.hwAddress != null) {
                md5.update(ni.hwAddress);
            }
        }
    }

    void updateWithNetworkData(final MessageDigest md5)
            throws SocketException {
        final List<Network.Interface.Data> networkInterfaces = Network.Interface.Data.gatherUsing(selector);
        networkInterfaces.sort(Comparator.comparing(a -> a.name));
        updateWithNetworkData(md5, networkInterfaces);
    }

    void updateWithHostName(final MessageDigest md5)
            throws UnknownHostException {
        final String hostName = java.net.InetAddress.getLocalHost()
                .getHostName();
        md5.update(hostName.getBytes(StandardCharsets.UTF_8), 0,
                hostName.getBytes(StandardCharsets.UTF_8).length);
    }

    void updateWithArchitecture(final MessageDigest md5) {
        final String architectureString = System.getProperty("os.arch");
        md5.update(architectureString.getBytes(StandardCharsets.UTF_8), 0,
                architectureString.getBytes(StandardCharsets.UTF_8).length);
    }
}
