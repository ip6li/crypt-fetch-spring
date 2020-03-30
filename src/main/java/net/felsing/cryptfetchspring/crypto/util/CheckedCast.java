
package net.felsing.cryptfetchspring.crypto.util;

import java.util.Map;

// See: https://stackoverflow.com/questions/25618452/cast-a-raw-map-to-a-generic-map-using-a-method-cleanly-and-safely-in-a-fail-ear

/***********************************************************************************
 * Provides type safe Map casting
 **********************************************************************************/

public class CheckedCast {

    public static final String LS = System.getProperty("line.separator");

    /** Check all contained items are claimed types and fail early if they aren't */
    public static <K, V> Map<K, V> castToMapOf(
            Class<K> clazzK,
            Class<V> clazzV,
            Map<?, ?> map) {

        for ( Map.Entry<?, ?> e: map.entrySet() ) {
            checkCast( clazzK, e.getKey() );
            checkCast( clazzV, e.getValue() );
        }

        @SuppressWarnings("unchecked")
        Map<K, V> result = (Map<K, V>) map;
        return result;
    }

    /** Check if cast would work */
    public static <T> void checkCast(Class<T> clazz, Object obj) {
        if ( !clazz.isInstance(obj) ) {
            throw new ClassCastException(
                    LS + "Expected: " + clazz.getName() +
                            LS + "Was:      " + obj.getClass().getName() +
                            LS + "Value:    " + obj
            );
        }
    }

}
