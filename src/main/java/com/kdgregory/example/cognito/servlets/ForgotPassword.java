// Copyright (c) Keith D Gregory, all rights reserved
package com.kdgregory.example.cognito.servlets;

import com.amazonaws.services.cognitoidp.model.*;
import net.sf.kdgcommons.lang.StringUtil;
import net.sf.kdgcommons.lang.ThreadUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


/**
 * This servlet handles normal user sign-in, based on username and password.
 */
public class ForgotPassword extends AbstractCognitoServlet {
    private static final long serialVersionUID = 1L;


    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        String emailAddress = request.getParameter(Constants.RequestParameters.EMAIL);
        if (StringUtil.isBlank(emailAddress)) {
            reportResult(response, Constants.ResponseMessages.INVALID_REQUEST);
            return;
        }

        logger.debug("Forgot password {}", emailAddress);

        try {
            AdminResetUserPasswordRequest req = new AdminResetUserPasswordRequest()
                .withUsername(emailAddress)
                .withUserPoolId(cognitoPoolId());

            AdminResetUserPasswordResult res = cognitoClient.adminResetUserPassword(req);

            logger.debug("ForgotPassword result: {}", res);
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
