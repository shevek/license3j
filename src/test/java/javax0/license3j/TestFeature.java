package javax0.license3j;

import javax0.license3j.Feature.Create;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

public class TestFeature {

    private static Method findMethod(final String methodName, Method[] methods, Class klass) {
        for (final Method method : methods) {
            if (method.getName().equalsIgnoreCase(methodName)) {
                return method;
            }
        }
        Assertions.fail("Method " + methodName + " was not found in class " + klass.getSimpleName());
        return null;
    }

    @Test
    @DisplayName("zero length binary feature, serialize and restore")
    public void testZeroLengthBinarySerializationAndRestore() {
        Feature sut = Create.binaryFeature("feature name", new byte[0]);
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals(0, res.getBinary().length);
    }

    @Test
    @DisplayName("one length binary feature, serialize and restore")
    public void testOneLengthBinarySerializationAndRestore() {
    	Feature sut = Create.binaryFeature("feature name", new byte[]{(byte) 0xFE});
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals(1, res.getBinary().length);
        Assertions.assertEquals((byte) 0xFE, res.getBinary()[0]);
    }

    @Test
    @DisplayName("UUID feature, serialize and restore")
    public void testUUID() {
    	Feature sut = Create.uuidFeature("feature name", new UUID(1L, 2L));
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals(new UUID(1L, 2L), res.getUUID());
    }

    @Test
    @DisplayName("UUID created from string")
    public void testUUIDFromString() {
    	Feature sut = Create.from("feature name:UUID=" + new UUID(1L, 2L));
        Assertions.assertTrue(sut.isUUID());
        Assertions.assertEquals(new UUID(1L, 2L), sut.getUUID());
    }

    @Test
    @DisplayName("binary feature, serialize and restore")
    public void testBinary() {
    	Feature sut = Create.binaryFeature("feature name", new byte[]{(byte) 0xFE, (byte) 0x53, (byte) 0xFF});
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals(3, res.getBinary().length);
        Assertions.assertEquals((byte) 0xFE, res.getBinary()[0]);
    }

    @Test
    @DisplayName("zero length string feature, serialize and restore")
    public void testZeroLengthStringSerializationAndRestore() {
    	Feature sut = Create.stringFeature("feature name", "");
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals(0, res.getString().length());
    }

    @Test
    @DisplayName("string feature, serialize and restore")
    public void testString() {
    	Feature sut = Create.stringFeature("feature name", "Hello, World!");
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals("Hello, World!", res.getString());
    }

    @Test
    @DisplayName("byte feature, serialize and restore")
    public void testByte() {
    	Feature sut = Create.byteFeature("feature name", (byte) 0xFE);
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals((byte) 0xFE, res.getByte());
    }

    @Test
    @DisplayName("short feature, serialize and restore")
    public void testShort() {
        Feature sut = Create.shortFeature("feature name", (short) 0xFEFE);
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals((short) 0xFEFE, res.getShort());
    }

    @Test
    @DisplayName("int feature, serialize and restore")
    public void testInt() {
        Feature sut = Create.intFeature("feature name", 0xFEFEFEFE);
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals(0xFEFEFEFE, res.getInt());
    }

    @Test
    @DisplayName("long feature, serialize and restore")
    public void testLong() {
        Feature sut = Create.longFeature("feature name", 0xFEFEFEFEFEFEFEFEL);
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals(0xFEFEFEFEFEFEFEFEL, res.getLong());
    }

    @Test
    @DisplayName("float feature, serialize and restore")
    public void testFloat() {
        Feature sut = Create.floatFeature("feature name", (float) 3.1415926);
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals((float) 3.1415926, res.getFloat());
    }

    @Test
    @DisplayName("double feature, serialize and restore")
    public void testDouble() {
        Feature sut = Create.doubleFeature("feature name", 3.1415926);
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals(3.1415926, res.getDouble());
    }

    @Test
    @DisplayName("BigInteger feature, serialize and restore")
    public void testBigInteger() {
    	BigInteger bi = new BigInteger("1377277372717772737372717727371723777273177172737727371984940591");
        Feature sut = Create.bigIntegerFeature("feature name", bi);
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals(bi, res.getBigInteger());
    }

    @Test
    @DisplayName("BigDecimal feature, serialize and restore")
    public void testBigDecimal() {
    	BigDecimal bd = new BigDecimal("3.141592653589793238462643383279502884197169399375105820974"
            + "944592307816406286208998628034825342117067982148086513282306647093844609550582"
            + "231725359408128481117450284102701938521105559644622948954930381964428810975665"
            + "93344612847564823378678316527120190914564856692346034861045432664");
        Feature sut = Create.bigDecimalFeature("feature name", bd);
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals(bd, res.getBigDecimal());
    }

    @Test
    @DisplayName("Date feature, serialize and restore")
    public void testDate() {
    	Date now = new Date();
        Feature sut = Create.dateFeature("feature name", now);
        byte[] b = sut.serialized();
        Feature res = Create.from(b);
        Assertions.assertEquals(now, res.getDate());
    }

    @Test
    @DisplayName("'from()' throws exception when the type is wrong value serialized")
    public void testWrongTypeDeserialization() {
        Feature sut = Create.binaryFeature("name", new byte[0]);
        byte[] b = sut.serialized();
        b[3] = 0;
        Assertions.assertThrows(IllegalArgumentException.class, () ->
            Create.from(b));
    }

    @Test
    @DisplayName("'from()' throws exception when array is too short")
    public void testShortDeserialization() {
    	byte[] b = new byte[4];
        Assertions.assertThrows(IllegalArgumentException.class, () ->
            Create.from(b));
    }

    @Test
    @DisplayName("'from()' throws exception when the array is truncated")
    public void testTruncatedDeserialization() {
        Feature sut = Create.binaryFeature("name", new byte[]{(byte) 0xFE, (byte) 0xFE});
        byte[] b = sut.serialized();
        byte[] c = Arrays.copyOf(b, b.length - 1);
        Assertions.assertThrows(IllegalArgumentException.class, () ->
            Create.from(c));
    }

    @Test
    @DisplayName("'from()' throws exception when the array is padded")
    public void testPaddedDeserialization() {
        Feature sut = Create.binaryFeature("name", new byte[]{(byte) 0xFE, (byte) 0xFE});
        byte[] b = sut.serialized();
        byte[] c = Arrays.copyOf(b, b.length + 1);
        Assertions.assertThrows(IllegalArgumentException.class, () ->
            Create.from(c));
    }

    @Test
    @DisplayName("Creating from null throws exception")
    public void creationFromNull() {
        for (Method method : Create.class.getMethods()) {
            if (Modifier.isStatic(method.getModifiers()) && method.getName().endsWith("Feature")) {
                Assertions.assertThrows(IllegalArgumentException.class,
                    () -> {
                        try {
                            method.invoke(null, "", null);
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    });
            }
        }
    }

    @Test
    @DisplayName("Check that all types have a factory method")
    public void testFactories() throws NoSuchFieldException, IllegalAccessException {
        Method[] methods = Feature.Create.class.getDeclaredMethods();
        for (final Object type : getTypeValues()) {
            final String methodName = type.toString() + "Feature";
            Method method = findMethod(methodName, methods, Feature.Create.class);
            Assertions.assertNotNull(method);
            int modifiers = method.getModifiers();
            Assertions.assertTrue(Modifier.isStatic(modifiers), "Method "
                + methodName + " is not static.");
            Assertions.assertTrue(Modifier.isPublic(modifiers), "Method "
                + methodName + " is not public.");
            Class<?>[] argtypes = method.getParameterTypes();
            Assertions.assertEquals(2, argtypes.length, "Factory method "
                + methodName + " should have exactly two arguments.");
            Assertions.assertEquals(String.class, argtypes[0], "Factory method "
                + methodName + " first argument has to be String.");
            if (argtypes[1].isArray()) {
                Field constField = Feature.class.getDeclaredField("VARIABLE_LENGTH");
                constField.setAccessible(true);
                final int VARIABLE_LENGTH = (int) constField.get(null);
                Assertions.assertEquals(VARIABLE_LENGTH, getFixedSize(type), "array accepting factory "
                    + methodName + " size has to be VARIABLE_LENGTH");
            }
        }
    }

    private Object getFixedSize(Object type) {
        try {
            final Class<?> typeClass = getTypeClass();
            final Field fixedSize = typeClass.getDeclaredField("fixedSize");
            fixedSize.setAccessible(true);
            return fixedSize.get(type);
        } catch (Exception e) {
            throw new AssertionError("Cannot get the types reflectively");
        }
    }

    private Object[] getTypeValues() {
        try {
            final Class<?> typeClass = getTypeClass();
            final Method values = typeClass.getDeclaredMethod("values");
            return (Object[]) values.invoke(null);
        } catch (Exception e) {
            throw new AssertionError("Cannot get the types reflectively");
        }
    }

    private Class<?> getTypeClass() throws ClassNotFoundException {
        return Class.forName(Feature.class.getName() + "$Type");
    }

    @Test
    @DisplayName("Check that all tests there are that serialize and deserialize some type")
    public void testSerializeDeserializeTestCompleteness() {
        Method[] methods = this.getClass().getDeclaredMethods();
        for (final Object type : getTypeValues()) {
            final String methodName = "test" + type.toString();
            Method method = findMethod(methodName, methods, this.getClass());
            Assertions.assertNotNull(method);
            int modifiers = method.getModifiers();
            Assertions.assertTrue(!Modifier.isStatic(modifiers), "Method " + methodName + " is static.");
            Assertions.assertTrue(Modifier.isPublic(modifiers), "Method " + methodName + " is not public.");
            Class<?>[] argtypes = method.getParameterTypes();
            Assertions.assertEquals(0, argtypes.length, "Test method " + methodName + " should not have parameters.");
        }
    }

    @Test
    @DisplayName("When asking for the wrong type method throws exception")
    public void testGetWrongType() throws IllegalAccessException, InvocationTargetException, InstantiationException {
        final Method[] methods = Feature.class.getDeclaredMethods();
        final Constructor<?> constructor = getFeatureConstructor();
        for (final Object type : getTypeValues()) {
            final Object sut = createFeatureSut(constructor, type);
            for (final Object wrongType : getTypeValues()) {
                if (type != wrongType) {
                    final String methodName = "get" + wrongType.toString();
                    final Method getMethod = findMethod(methodName, methods, Feature.class);
                    Assertions.assertNotNull(getMethod);
                    final int modifiers = getMethod.getModifiers();
                    Assertions.assertTrue(Modifier.isPublic(modifiers), "Method " + getMethod.getName() + " is supposed to be public.");
                    Assertions.assertThrows(IllegalArgumentException.class, () -> {
                        try {
                            getMethod.invoke(sut);
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    }, "No exception was thrown when calling " + getMethod.getName() + " for type " + wrongType);
                }
            }
        }
    }

    private Object createFeatureSut(Constructor<?> constructor, Object type)
        throws InstantiationException, IllegalAccessException, InvocationTargetException {
        return constructor.newInstance("name", type, new byte[]{0x00});
    }


    @Test
    @DisplayName("Testing type with isType() method works")
    public void testTestType() throws IllegalAccessException, InvocationTargetException, InstantiationException {
        final Method[] methods = Feature.class.getDeclaredMethods();
        final Constructor<?> constructor = getFeatureConstructor();
        for (final Object type : getTypeValues()) {
            final Object sut = createFeatureSut(constructor, type);
            for (final Object testType : getTypeValues()) {
                final String methodName = "is" + testType.toString();
                final Method getMethod = findMethod(methodName, methods, Feature.class);
                Assertions.assertNotNull(getMethod);
                final int modifiers = getMethod.getModifiers();
                Assertions.assertTrue(Modifier.isPublic(modifiers),
                    "Method " + getMethod.getName() + " is supposed to be public.");
                Assertions.assertEquals(getMethod.invoke(sut), (testType == type), "method " + getMethod.getName() +
                    " does not test properly a Feature that is of type " + testType);
            }
        }
    }

    private Constructor<?> getFeatureConstructor() {
        final Constructor<?>[] constructors = Feature.class.getDeclaredConstructors();
        final Constructor<?> constructor = Arrays.stream(constructors)
            .filter(c -> c.getParameterCount() == 3)
            .findAny()
            .orElseThrow(() -> new AssertionFailedError("There is no appropriate constructor in the class Feature"));
        final int constructorModifiers = constructor.getModifiers();
        Assertions.assertTrue(Modifier.isPrivate(constructorModifiers), "The constructor of Feature has to be private.");
        constructor.setAccessible(true);
        return constructor;
    }

    @Test
    @DisplayName("Binary feature is converted to string")
    public void testBinaryToString() {
        final Feature sut = Feature.Create.binaryFeature("name", new byte[]{(byte) 0xfe, (byte) 0x11, (byte) 0xAf});
        Assertions.assertEquals("name:BINARY=/hGv", sut.toString());
    }

    @Test
    @DisplayName("Binary feature is converted from string")
    public void testBinaryFromString() {
        final Feature sut = Feature.Create.from("name:BINARY=/hGv");
        Assertions.assertEquals("name", sut.name());
        Assertions.assertTrue(sut.isBinary());
        byte[] b = sut.getBinary();
        Assertions.assertAll(
            () -> Assertions.assertEquals(b[0], (byte) 0xfe),
            () -> Assertions.assertEquals(b[1], (byte) 0x11),
            () -> Assertions.assertEquals(b[2], (byte) 0xaf)
        );
    }

    @Test
    @DisplayName("String feature is converted from string")
    public void testStringFromString() {
        final Feature sut = Feature.Create.from("name:STRING=test \"string\\");
        Assertions.assertEquals("name", sut.name());
        Assertions.assertTrue(sut.isString());
        Assertions.assertEquals("test \"string\\", sut.getString());
    }

    @Test
    @DisplayName("byte feature is converted from string")
    public void testByteFromString() {
        final Feature sut = Feature.Create.from("name:BYTE=0xFE");
        Assertions.assertEquals("name", sut.name());
        Assertions.assertTrue(sut.isByte());
        Assertions.assertEquals((byte) 0xFE, sut.getByte());
    }

    @Test
    @DisplayName("short feature is converted from string")
    public void testShortFromString() {
        final Feature sut = Feature.Create.from("name:SHORT=0xFEFE");
        Assertions.assertEquals("name", sut.name());
        Assertions.assertTrue(sut.isShort());
        Assertions.assertEquals((short) 0xfefe, sut.getShort());
    }

    @Test
    @DisplayName("int feature is converted from string")
    public void testIntFromString() {
        final Feature sut = Feature.Create.from("name:INT=65342");
        Assertions.assertEquals("name", sut.name());
        Assertions.assertTrue(sut.isInt());
        Assertions.assertEquals(65342, sut.getInt());
    }

    @Test
    @DisplayName("long feature is converted from string")
    public void testLongFromString() {
        final Feature sut = Feature.Create.from("name:LONG=6534232122");
        Assertions.assertEquals("name", sut.name());
        Assertions.assertTrue(sut.isLong());
        Assertions.assertEquals(6534232122L, sut.getLong());
    }

    @Test
    @DisplayName("float feature is converted from string")
    public void testFloatFromString() {
        final Feature sut = Feature.Create.from("name:FLOAT=3.14");
        Assertions.assertEquals("name", sut.name());
        Assertions.assertTrue(sut.isFloat());
        Assertions.assertEquals(3.14f, sut.getFloat());
    }

    @Test
    @DisplayName("double feature is converted from string")
    public void testDoubleFromString() {
        final Feature sut = Feature.Create.from("name:DOUBLE=3.14d");
        Assertions.assertEquals("name", sut.name());
        Assertions.assertTrue(sut.isDouble());
        Assertions.assertEquals(3.14, sut.getDouble());
    }

    @Test
    @DisplayName("bigInteger feature is converted from string")
    public void testBigIntegerFromString() {
        final Feature sut = Feature.Create.from("name:BIGINTEGER=123456789012345678901234567890");
        Assertions.assertEquals("name", sut.name());
        Assertions.assertTrue(sut.isBigInteger());
        Assertions.assertEquals(new BigInteger("123456789012345678901234567890"), sut.getBigInteger());
    }

    @Test
    @DisplayName("bigDecimal feature is converted from string")
    public void testBigDecimalFromString() {
        final Feature sut = Feature.Create.from(
            "name:BIGDECIMAL=123456789012345678901234567890.123456789012345678901234567890");
        Assertions.assertEquals("name", sut.name());
        Assertions.assertTrue(sut.isBigDecimal());
        Assertions.assertEquals(new BigDecimal("123456789012345678901234567890.123456789012345678901234567890"),
            sut.getBigDecimal());
    }

    @Test
    @DisplayName("date feature is converted from string")
    public void testDateFromString() {
        int tzoff = 3600 * 1000;    // The original author was clearly in UTC+1 or UTC-1.
        final Feature sut1 = Feature.Create.from("name:DATE=2018-12-17 12:55:19.295");
        Assertions.assertEquals("name", sut1.name());
        Assertions.assertTrue(sut1.isDate());
        Assertions.assertEquals(new Date(1545047719295L + tzoff), sut1.getDate());

        final Feature sut2 = Feature.Create.from("name:DATE=2018-12-17 12:55:19");
        Assertions.assertEquals("name", sut2.name());
        Assertions.assertTrue(sut2.isDate());
        Assertions.assertEquals(new Date(1545047719000L + tzoff), sut2.getDate());

        final Feature sut3 = Feature.Create.from("name:DATE=2018-12-17 12:55");
        Assertions.assertEquals("name", sut3.name());
        Assertions.assertTrue(sut3.isDate());
        Assertions.assertEquals(new Date(1545047700000L + tzoff), sut3.getDate());
    }


    @Test
    @DisplayName("String feature is converted to string")
    public void testStringToString() {
        final Feature sut = Feature.Create.stringFeature("name", "test \"string\\ ");
        Assertions.assertEquals("name=test \"string\\ ", sut.toString());
    }

    @Test
    @DisplayName("Byte feature is converted to string")
    public void testByteToString() {
        final Feature sut = Feature.Create.byteFeature("name", (byte) 0xfe);
        Assertions.assertEquals("name:BYTE=0xFE", sut.toString());
    }

    @Test
    @DisplayName("Short feature is converted to string")
    public void testShortToString() {
        final Feature sut = Feature.Create.shortFeature("name", (short) 11);
        Assertions.assertEquals("name:SHORT=11", sut.toString());
    }

    @Test
    @DisplayName("Int feature is converted to string")
    public void testIntToString() {
        final Feature sut = Feature.Create.intFeature("name", 6000);
        Assertions.assertEquals("name:INT=6000", sut.toString());
    }

    @Test
    @DisplayName("Long feature is converted to string")
    public void testLongToString() {
        final Feature sut = Feature.Create.longFeature("name", 6000000000L);
        Assertions.assertEquals("name:LONG=6000000000", sut.toString());
    }

    @Test
    @DisplayName("Float feature is converted to string")
    public void testFloatToString() {
        final Feature sut = Feature.Create.floatFeature("name", 3.1415926f);
        Assertions.assertEquals("name:FLOAT=3.1415925", sut.toString());
    }

    @Test
    @DisplayName("Double feature is converted to string")
    public void testDoubleToString() {
        final Feature sut = Feature.Create.doubleFeature("name", 3.1415926d);
        Assertions.assertEquals("name:DOUBLE=3.1415926", sut.toString());
    }

    @Test
    @DisplayName("Biginteger feature is converted to string")
    public void testBigintegerToString() {
        final Feature sut = Feature.Create.bigIntegerFeature("name",
            new BigInteger("123456789012345678901234567890123456789012345678901234567890123456789"));
        Assertions.assertEquals("name:BIGINTEGER=123456789012345678901234567890123456789012345678901234567890123456789", sut.toString());
    }

    @Test
    @DisplayName("Bigdecimal feature is converted to string")
    public void testBigdecimalToString() {
        final Feature sut = Feature.Create.bigDecimalFeature("name",
            new BigDecimal("789012345678901234567890123456789.0123456789012345678901234567890123456789"));
        Assertions.assertEquals("name:BIGDECIMAL=789012345678901234567890123456789.0123456789012345678901234567890123456789", sut.toString());
    }

    @Test
    @DisplayName("Date feature is converted to string")
    public void testDateToString() {
        final Feature sut = Feature.Create.dateFeature("now", new Date(1545047719295L));
        Assertions.assertEquals("now:DATE=2018-12-17 12:55:19.295", sut.toString());
    }
}

