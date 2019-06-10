package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.CustomerDao;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

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
            return this.customerDao.createUser(customerEntity);
        }
    }

}
