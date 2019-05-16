package javax0.license3j.hardware;

import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * Calculate a UUID that is specific to the machne. Note that machines are hard to identify and therefore
 * there is no guarantee that two machines will not ever have the same UUID and also there is no guarantee that
 * a single machine will always have the same UUID. The first one is less of a problem. The later, the stability
 * of the UUID of a single machine can be managed with the parameters of the calculator, controlling what the
 * calculation takes into account. The less parameters you select the more stable the UUID will be. On the other hand
 * the less parameter you use the more machines may end-up having the same UUID.
 *
 * Machne UUIDs may be used to restrict the usage of a software to certain machines.
 *
 */
public class UUIDCalculator {
    private final HashCalculator calculator;

    public UUIDCalculator(Network.Interface.Selector selector) {
        this.calculator = new HashCalculator(selector);
    }

    public UUID getMachineId(boolean useNetwork, boolean useHostName, boolean useArchitecture)
        throws SocketException, UnknownHostException, NoSuchAlgorithmException {
        final MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.reset();
        if (useNetwork) {
            calculator.updateWithNetworkData(md5);
        }
        if (useHostName) {
            calculator.updateWithHostName(md5);
        }
        if (useArchitecture) {
            calculator.updateWithArchitecture(md5);
        }
        final byte[] digest = md5.digest();
        return UUID.nameUUIDFromBytes(digest);
    }

    public String getMachineIdString(boolean useNetwork, boolean useHostName, boolean useArchitecture) throws
        SocketException, UnknownHostException, NoSuchAlgorithmException {
        final UUID uuid = getMachineId(useNetwork, useHostName, useArchitecture);
        if (uuid != null) {
            return uuid.toString();
        } else {
            return null;
        }
    }

    public boolean assertUUID(final UUID uuid, boolean useNetwork, boolean useHostName, boolean useArchitecture)
        throws SocketException, UnknownHostException, NoSuchAlgorithmException {
        final UUID machineUUID = getMachineId(useNetwork, useHostName, useArchitecture);
        return machineUUID != null && machineUUID.equals(uuid);
    }

    public boolean assertUUID(final String uuid, boolean useNetwork, boolean useHostName, boolean useArchitecture) {
        try {
            return assertUUID(java.util.UUID.fromString(uuid), useNetwork, useHostName, useArchitecture);
        } catch (Exception e) {
            return false;
        }
    }
}
