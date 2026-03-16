/*
 * Copyright (c) 2025 OpenHitls
 * SDF4J is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package org.openhitls.sdf4j.jce;

import java.security.GeneralSecurityException;

/**
 * SDF JCE Exception
 */
public class SDFJceException extends GeneralSecurityException {

    private static final long serialVersionUID = 1L;

    private final int errorCode;

    public SDFJceException(int errorCode, String message) {
        super(String.format("SDF error 0x%08X: %s", errorCode, message));
        this.errorCode = errorCode;
    }

    public SDFJceException(String message) {
        super(message);
        this.errorCode = 0;
    }

    public SDFJceException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = 0;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
