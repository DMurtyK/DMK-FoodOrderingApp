package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.CustomerDao;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthTokenEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.UpdateCustomerException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;

@Service
public class ChangePasswordBusinessService {

    //Respective Data access object has been autowired to access the method defined in respective Dao
    @Autowired
    private CustomerDao customerDao;

    @Autowired
    private PasswordCryptographyProvider passwordCryptographyProvider;



    //Validates Customer and updates password as given by the Customer

    @Transactional(propagation = Propagation.REQUIRED)

    public CustomerEntity updateCustomerPassword(final String accessToken, final String oldPassword,final String newPassword) throws AuthorizationFailedException, UpdateCustomerException {
        CustomerAuthTokenEntity customerAuthTokenEntity = customerDao.getCustomerAuthToken(accessToken);
        CustomerEntity customerEntity = customerAuthTokenEntity.getCustomer();

        System.out.println(oldPassword);
        System.out.println(customerAuthTokenEntity.getCustomer().getPassword());
        System.out.println(customerAuthTokenEntity.getCustomer().getSalt());
        final String decryptedPassword = passwordCryptographyProvider.encrypt(oldPassword,customerAuthTokenEntity.getCustomer().getSalt());
        System.out.println(decryptedPassword);

        if (oldPassword == null || newPassword == null) {
            throw new UpdateCustomerException("UCR-003", "No field should be empty");
        }
        if (customerAuthTokenEntity == null) {
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in.");
        } else if (customerAuthTokenEntity != null && customerAuthTokenEntity.getLogoutAt() != null) {
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
        } else if (customerAuthTokenEntity != null && ZonedDateTime.now().isAfter(customerAuthTokenEntity.getExpiresAt())) {
            throw new AuthorizationFailedException("ATHR-003", "Your session is expired. Log in again to access this endpoint.");
        } else if(!customerEntity.checkPasswordIsValid(newPassword)) {
            throw new UpdateCustomerException("UCR-001","Weak password!");
        } else if(!customerAuthTokenEntity.getCustomer().getPassword().matches(oldPassword) ){
        throw new UpdateCustomerException("UCR-004","Incorrect old password!");
        }
        else {

            String[] encryptedText = passwordCryptographyProvider.encrypt(newPassword);
            customerEntity.setSalt(encryptedText[0]);
            customerEntity.setPassword(encryptedText[1]);
             customerDao.updateCustomer(customerEntity);


            //customerAuthTokenEntity.getCustomer().setPassword(newPassword);
            return customerAuthTokenEntity.getCustomer();
        }

    }


}