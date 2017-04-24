// Copyright (c) Keith D Gregory, all rights reserved
package com.kdgregory.example.cognito.servlets;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.amazonaws.services.cognitoidp.model.*;
import net.sf.kdgcommons.lang.StringUtil;
import net.sf.kdgcommons.lang.ThreadUtil;


/**
 * This servlet finishes the signup process for a new user, changing the temporary
 * password to a final password.
 */
public class ConfirmSignUp extends AbstractCognitoServlet {
    private static final long serialVersionUID = 1L;


    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
//        String emailAddress = request.getParameter(Constants.RequestParameters.EMAIL);
//        String tempPassword = request.getParameter(Constants.RequestParameters.TEMPORARY_PASSWORD);
//        String finalPassword = request.getParameter(Constants.RequestParameters.PASSWORD);
//        if (StringUtil.isBlank(emailAddress) || StringUtil.isBlank(tempPassword) || StringUtil.isBlank(finalPassword)) {
//            reportResult(response, Constants.ResponseMessages.INVALID_REQUEST);
//            return;
//        }

//        logger.debug("confirming signup of user {}", emailAddress);

        try {
            logger.debug("\n\n\nLogin by username: {} / {}\n", SignUp.USERNAME, SignUp.TEMP_PASSWORD);
            Map<String, String> initialParams = new HashMap();
            initialParams.put("USERNAME", SignUp.USERNAME);
            initialParams.put("PASSWORD", SignUp.TEMP_PASSWORD);

            AdminInitiateAuthRequest initialRequest = new AdminInitiateAuthRequest()
                .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                .withAuthParameters(initialParams)
                .withClientId(cognitoClientId())
                .withUserPoolId(cognitoPoolId());

            AdminInitiateAuthResult initialResponse = cognitoClient.adminInitiateAuth(initialRequest);

            logger.debug("SUCCESS");

            if (!ChallengeNameType.NEW_PASSWORD_REQUIRED.name().equals(initialResponse.getChallengeName())) {
                throw new RuntimeException("unexpected challenge: " + initialResponse.getChallengeName());
            }

            Map<String, String> challengeResponses2 = new HashMap<String, String>();
            challengeResponses2.put("USERNAME", SignUp.USERNAME);
            challengeResponses2.put("PASSWORD", SignUp.TEMP_PASSWORD);
            challengeResponses2.put("NEW_PASSWORD", "jeff1234");

            AdminRespondToAuthChallengeRequest finalRequest2 = new AdminRespondToAuthChallengeRequest()
                .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                .withChallengeResponses(challengeResponses2)
                .withClientId(cognitoClientId())
                .withUserPoolId(cognitoPoolId())
                .withSession(initialResponse.getSession());

            AdminRespondToAuthChallengeResult challengeResponse2 = cognitoClient.adminRespondToAuthChallenge(finalRequest2);

            if (StringUtil.isBlank(challengeResponse2.getChallengeName())) {
                logger.debug("User logged in.");
//                updateCredentialCookies(response, challengeResponse.getAuthenticationResult());
//                reportResult(response, Constants.ResponseMessages.LOGGED_IN);
            } else {
                throw new RuntimeException("unexpected challenge: " + challengeResponse2.getChallengeName());
            }

            logger.debug("Changing email");

            AdminUpdateUserAttributesRequest changeEmail = new AdminUpdateUserAttributesRequest()
                .withUsername(SignUp.USERNAME)
                .withUserPoolId(cognitoPoolId())
                .withUserAttributes(
                    new AttributeType().withName("email").withValue("jeff@schwartz-tribe.com"),
                    new AttributeType().withName("email_verified").withValue("true")
                );
            AdminUpdateUserAttributesResult res = cognitoClient.adminUpdateUserAttributes(changeEmail);

            logger.debug("Changed email address to jeff@schwartz-tribe.com: {}", res);

//
//            Map<String, String> challengeResponses = new HashMap<String, String>();
//            challengeResponses.put("USERNAME", SignUp.USERNAME);
//            challengeResponses.put("PASSWORD", SignUp.TEMP_PASSWORD);
//            challengeResponses.put("NEW_PASSWORD", "jeff1234");
//
//
//            AdminRespondToAuthChallengeRequest finalRequest = new AdminRespondToAuthChallengeRequest()
//                .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
//                .withChallengeResponses(challengeResponses)
//                .withClientId(cognitoClientId())
//                .withUserPoolId(cognitoPoolId())
//                .withSession(initialResponse.getSession());
//
//            AdminRespondToAuthChallengeResult challengeResponse = cognitoClient.adminRespondToAuthChallenge(finalRequest);
//
//            if (StringUtil.isBlank(challengeResponse.getChallengeName())) {
//                updateCredentialCookies(response, challengeResponse.getAuthenticationResult());
//                reportResult(response, Constants.ResponseMessages.LOGGED_IN);
//            } else {
//                throw new RuntimeException("unexpected challenge: " + challengeResponse.getChallengeName());
//            }



        } catch (InvalidPasswordException ex) {
//            logger.debug("{} submitted invalid password", emailAddress);
            reportResult(response, Constants.ResponseMessages.INVALID_PASSWORD);
        } catch (UserNotFoundException ex) {
//            logger.debug("not found: {}", emailAddress);
            reportResult(response, Constants.ResponseMessages.NO_SUCH_USER);
        } catch (NotAuthorizedException ex) {
//            logger.debug("invalid credentials: {}", emailAddress);
            reportResult(response, Constants.ResponseMessages.NO_SUCH_USER);
        } catch (TooManyRequestsException ex) {
            logger.warn("caught TooManyRequestsException, delaying then retrying");
            ThreadUtil.sleepQuietly(250);
            doPost(request, response);
        }
    }


    @Override
    public String getServletInfo() {
        return "Handles second stage of user signup, replacing temporary password by final";
    }

}
