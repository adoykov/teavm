/*
 *  Copyright 2021 Alexander.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.teavm.classlib.java.security.cert;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorSpi;
import sun.security.jca.GetInstance;

public class TCertPathValidator {

    private static final String CPV_TYPE = "certpathvalidator.type";
    private final CertPathValidatorSpi validatorSpi;
    private final Provider provider;
    private final String algorithm;

    private TCertPathValidator(CertPathValidatorSpi validatorSpi,
            Provider provider, String algorithm)
    {
        this.validatorSpi = validatorSpi;
        this.provider = provider;
        this.algorithm = algorithm;
    }

    public static TCertPathValidator getInstance(String algorithm)
            throws NoSuchAlgorithmException {
        GetInstance.Instance instance = GetInstance.getInstance("TCertPathValidator",
                CertPathValidatorSpi.class, algorithm);
        return new TCertPathValidator((CertPathValidatorSpi)instance.impl,
                instance.provider, algorithm);
    }
}
