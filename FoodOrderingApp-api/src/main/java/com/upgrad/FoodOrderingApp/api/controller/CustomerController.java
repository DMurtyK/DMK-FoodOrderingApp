package com.upgrad.FoodOrderingApp.api.controller;


import com.upgrad.FoodOrderingApp.api.model.LoginResponse;
import com.upgrad.FoodOrderingApp.api.model.SignupCustomerRequest;
import com.upgrad.FoodOrderingApp.api.model.SignupCustomerResponse;
import com.upgrad.FoodOrderingApp.service.businness.LoginBusinessService;
import com.upgrad.FoodOrderingApp.service.businness.SignupCustomerBusinessService;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthTokenEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthenticationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@RestController
@CrossOrigin
@RequestMapping("/")
public class CustomerController {

    @Autowired
    private SignupCustomerBusinessService signupCustomerBusinessService;

    @Autowired
    private LoginBusinessService loginBusinessService;



    // SignUp end point definition
    @RequestMapping(method = RequestMethod.POST,path = "/customer/signup",consumes = MediaType.APPLICATION_JSON_UTF8_VALUE,produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<SignupCustomerResponse> signup(final SignupCustomerRequest signupCustomerRequest) throws SignUpRestrictedException {

        final CustomerEntity customerEntity = new CustomerEntity();


        customerEntity.setUuid(UUID.randomUUID().toString());
        customerEntity.setFirstname(signupCustomerRequest.getFirstName());
        customerEntity.setLastname(signupCustomerRequest.getLastName());
        customerEntity.setEmail(signupCustomerRequest.getEmailAddress());
        customerEntity.setPassword(signupCustomerRequest.getPassword());
        customerEntity.setContactnumber(signupCustomerRequest.getContactNumber());
        customerEntity.setSalt("1234");

        final CustomerEntity createdCustomerEntity = signupCustomerBusinessService.signup(customerEntity,signupCustomerRequest.getFirstName(),signupCustomerRequest.getLastName(),signupCustomerRequest.getContactNumber(),signupCustomerRequest.getEmailAddress(),signupCustomerRequest.getPassword());

        SignupCustomerResponse userResponse = new SignupCustomerResponse().id(createdCustomerEntity.getUuid()).status("CUSTOMER SUCCESSFULLY REGISTERED");

        return new ResponseEntity<SignupCustomerResponse>(userResponse,HttpStatus.CREATED);
    }

    // login end point definition

    //login method is used to perform a Basic authorization when the customer tries to login for the first time
    @RequestMapping(method = RequestMethod.POST, path = "/customer/login", produces = MediaType.APPLICATION_JSON_UTF8_VALUE,consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<LoginResponse> login(@RequestHeader("Authorization") final String authorization) throws AuthenticationFailedException {
        byte[] decode = Base64.getDecoder().decode(authorization.split("Basic ")[1]);
        String decodedText = new String(decode);
        String[] decodedArray = decodedText.split(":");
        if (loginBusinessService.checkAuthenticationFormat(authorization) == true ) {
            final CustomerAuthTokenEntity customerAuthToken = loginBusinessService.authenticate(decodedArray[0], decodedArray[1]);

            CustomerEntity customerEntity = customerAuthToken.getCustomer();

            LoginResponse loginResponse = new LoginResponse()
                    .firstName(customerEntity.getFirstname())
                    .lastName(customerEntity.getLastname())
                    .emailAddress(customerEntity.getEmail())
                    .contactNumber(customerEntity.getContactnumber())
                    .id(customerEntity.getUuid())
                    .message("LOGGED IN SUCCESSFULLY");


            HttpHeaders headers = new HttpHeaders();
            List<String> header = new ArrayList<>();
            header.add("access-token");
            headers.setAccessControlExposeHeaders(header);
            headers.add("access-token", customerAuthToken.getAccessToken());

            return new ResponseEntity<LoginResponse>(loginResponse, headers, HttpStatus.OK);
        }
        else{
            throw new AuthenticationFailedException("ATH-003", "Incorrect format of decoded customer name and password");
        }
    }






}
