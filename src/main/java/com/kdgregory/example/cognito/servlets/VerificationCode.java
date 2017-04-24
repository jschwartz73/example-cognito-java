// Copyright (c) Keith D Gregory, all rights reserved
package com.kdgregory.example.cognito.servlets;

import com.amazonaws.services.cognitoidp.model.*;
import net.sf.kdgcommons.lang.StringUtil;
import net.sf.kdgcommons.lang.ThreadUtil;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;


/**
 * This servlet handles normal user sign-in, based on username and password.
 */
public class VerificationCode extends AbstractCognitoServlet {
    private static final long serialVersionUID = 1L;


    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        String emailAddress = request.getParameter(Constants.RequestParameters.EMAIL);
        String verificationCode = request.getParameter(Constants.RequestParameters.PASSWORD);
        if (StringUtil.isBlank(emailAddress) || StringUtil.isBlank(verificationCode)) {
            reportResult(response, Constants.ResponseMessages.INVALID_REQUEST);
            return;
        }

        logger.debug("verification {}", emailAddress);

        try {
            Map<String, String> authParams = new HashMap<String, String>();
            authParams.put("USERNAME", emailAddress);
            authParams.put("EMAIL", emailAddress);
            authParams.put("PASSWORD", "jeff1234");

            ConfirmForgotPasswordRequest req = new ConfirmForgotPasswordRequest()
                .withClientId(cognitoClientId())
                .withConfirmationCode(verificationCode)
                .withUsername(emailAddress)
                .withPassword("jeff12345");

            ConfirmForgotPasswordResult res = cognitoClient.confirmForgotPassword(req);
            logger.debug("REs: {}", res);
        } catch (UserNotFoundException ex) {
            logger.debug("not found: {}", emailAddress);
            reportResult(response, Constants.ResponseMessages.NO_SUCH_USER);
        } catch (NotAuthorizedException ex) {
            logger.debug("invalid credentials: {}", emailAddress);
            reportResult(response, Constants.ResponseMessages.NO_SUCH_USER);
        } catch (TooManyRequestsException ex) {
            logger.warn("caught TooManyRequestsException, delaying then retrying");
            ThreadUtil.sleepQuietly(250);
            doPost(request, response);
        }
    }


    @Override
    public String getServletInfo() {
        return "Handles user signin";
    }

}
