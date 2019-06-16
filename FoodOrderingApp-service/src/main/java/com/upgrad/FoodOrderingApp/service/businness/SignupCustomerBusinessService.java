package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.CustomerDao;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthTokenEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import com.upgrad.FoodOrderingApp.service.exception.UpdateCustomerException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;
import java.util.regex.Pattern;

@Service
public class SignupCustomerBusinessService  {


    @Autowired
    private CustomerDao customerDao;

    @Autowired
    private PasswordCryptographyProvider passwordCryptographyProvider;


    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerEntity signup(CustomerEntity customerEntity,String firstName,String lastName,String contactNumber,String emailAddress,String password) throws SignUpRestrictedException {

        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\."+
                "[a-zA-Z0-9_+&*-]+)*@" +
                "(?:[a-zA-Z0-9-]+\\.)+[a-z" +
                "A-Z]{2,7}$";

        Pattern pat = Pattern.compile(emailRegex);

        //matches 10-digit numbers only
        String regexStr = "^[0-9]{10}$";


        if (customerDao.getCustomerByContactNumber(contactNumber) != null) {
            throw new SignUpRestrictedException("SGR-001", "This contact number is already registered! Try other contact number.");
        }
        else if(firstName == null || emailAddress == null || contactNumber == null ||password == null){
            throw new SignUpRestrictedException("SGR-005", "Except last name all fields should be filled");
        }
        else if (!pat.matcher(emailAddress).matches())
        {
            throw new SignUpRestrictedException("SGR-002","Invalid email-id format!");
        }
        else if (!contactNumber.matches(regexStr))
        {
            throw new SignUpRestrictedException("SGR-003","Invalid contact number!");
        }
        else  if( password.length() < 8 || !password.matches("(?=.*[0-9]).*") || !password.matches("(?=.*[A-Z]).*")|| !password.matches("(?=.*[~!@#$%^&*()_-]).*") ){
            throw new SignUpRestrictedException("SGR-004","Weak password");
        }
        else
        {
            String[] encryptedText = passwordCryptographyProvider.encrypt(customerEntity.getPassword());
            customerEntity.setSalt(encryptedText[0]);
            customerEntity.setPassword(encryptedText[1]);
            return customerDao.createUser(customerEntity);
        }
    }

    //getCustomer method is used to perform Bearer authorization
    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerEntity getCustomer(final String accessToken) throws AuthorizationFailedException {
        CustomerAuthTokenEntity customerAuthEntity = customerDao.getCustomerAuthToken(accessToken);
        //If the access token provided by the customer does not exist in the database
        if (customerAuthEntity == null) {
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in.");
            //If the access token provided by the customer exists in the database, but the customer has already logged out
        } else if (customerAuthEntity != null && customerAuthEntity.getLogoutAt() != null) {
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
            //If the access token provided by the customer exists in the database, but the session has expired
        } else if (customerAuthEntity != null && ZonedDateTime.now().isAfter(customerAuthEntity.getExpiresAt())) {
            throw new AuthorizationFailedException("ATHR-003", "Your session is expired. Log in again to access this endpoint.");
        } else {
            return customerAuthEntity.getCustomer();
        }
    }


    //updateCustomer method is used to update a customer's firstname and/or lastname
    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerEntity updateCustomer(final CustomerEntity customerEntity) throws UpdateCustomerException {
        if (customerEntity.getFirstname().isEmpty()) {
            throw new UpdateCustomerException("UCR-002", "First name field should not be empty");
        } else {
            final CustomerEntity updatedCustomerEntity = new CustomerEntity();
            updatedCustomerEntity.setFirstname(customerEntity.getFirstname());
            if(!customerEntity.getLastname().isEmpty()) {
                updatedCustomerEntity.setLastname(customerEntity.getLastname());
            }
            updatedCustomerEntity.setUuid(customerEntity.getUuid());
            return updatedCustomerEntity;
        }
    }

    //updateCustomerPassword updates password as given by the Customer in newPassword field
    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerEntity updateCustomerPassword(final String oldPassword,final String newPassword, final CustomerEntity customerEntity) throws  UpdateCustomerException {
        if (oldPassword.isEmpty() || newPassword.isEmpty()) {
            throw new UpdateCustomerException("UCR-003", "No field should be empty");
        } else if(newPassword.length() < 8 || !newPassword.matches("(?=.*[0-9]).*") || !newPassword.matches("(?=.*[A-Z]).*")|| !newPassword.matches("(?=.*[~!@#$%^&*()_-]).*")) {
            throw new UpdateCustomerException("UCR-001","Weak password!");
        } else if(!oldPassword.equals(customerEntity.getPassword()) ){
            throw new UpdateCustomerException("UCR-004","Incorrect old password!");
        } else {
            customerEntity.setPassword(newPassword);
            return customerEntity;
        }
    }
}
