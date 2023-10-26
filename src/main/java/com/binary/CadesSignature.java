package com.binary;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Iterator;
import com.fasterxml.jackson.databind.*;


public class CadesSignature {
    public boolean validateCADESignature(String inputSignature, String inputData) throws CMSException,
            CertificateException, OperatorCreationException  {
        Boolean validated = false;
        CAdESSignature cAdESSignature;
//Base64 decode of input signature
        cAdESSignature = new CAdESSignature(Base64.getDecoder().decode(inputSignature));
        ObjectMapper mapper = new ObjectMapper();
        mapper.findAndRegisterModules();
//Extracting the Data enveloped inside signature
        String extractedData = mapper
                .convertValue(new String((byte[])
                        cAdESSignature.getCmsSignedData().getSignedContent().getContent(),
                        StandardCharsets.UTF_8), String.class);

//Is Input Data matching with the data retrieved from Signature?
// If yes, then first criteria is Valid
        if (inputData.equalsIgnoreCase(extractedData)) {
            System.out.println("Input Data matches with the data retrieved from Signature");
//Verify the Certificase of Signature
            CMSSignedData signedData = cAdESSignature.getCmsSignedData();
            Store<X509CertificateHolder> store = signedData.getCertificates();
            SignerInformationStore signers = signedData.getSignerInfos();
            Collection<SignerInformation> c = signers.getSigners();
            for (SignerInformation signer : c) {
                Collection certCollection = store.getMatches(signer.getSID());
                Iterator certIt = certCollection.iterator();
                X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
                X509Certificate certFromSignedData;
                certFromSignedData = new
                        JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
                if (signer
                        .verify(new
                                JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certFromSignedData))) {
//Signature is verified (second criteria met)
                    System.out.println("Signature verified");
                    validated = true;
                } else {
                    System.out.println("Signature verification failed");
                }
            }
        }
        return validated; //Return the result of Verification
    }

}
