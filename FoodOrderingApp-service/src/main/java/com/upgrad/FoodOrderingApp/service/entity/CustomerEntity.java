package com.upgrad.FoodOrderingApp.service.entity;


import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringExclude;
import org.apache.commons.lang3.builder.ToStringStyle;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
//import javax.validation.constraints.Pattern;
import java.util.Base64;
import java.util.regex.Matcher;

import java.util.regex.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;

@Entity
@Table(name = "customer")
@NamedQueries(
        {
                @NamedQuery(name = "customerByContactNumber", query = "select u from CustomerEntity u where u.contact_number =:contact_number")
        }
)
public class CustomerEntity implements Serializable{

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "uuid")
    @NotNull
    @Size(max = 200)
    private String uuid;

    @Column(name = "firstname")
    @NotNull
    @Size(max = 30)
    private String firstname;

    @Column(name = "lastname")
    @NotNull
    @Size(max = 30)
    private String lastname;

    @Column(name = "email")
    @Size(max=50)
    private String email;

    @Column(name = "contact_number")
    @NotNull
    @Size(max=30)
    private String contact_number;

    @Column(name = "password")
    @ToStringExclude
    @Size(max = 255)
    private String password;

    @Column(name = "salt")
    @NotNull
    @Size(max = 200)
    @ToStringExclude
    private String salt;


    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getContactnumber() {
        return contact_number;
    }

    public void setContactnumber(String contact_number) {
        this.contact_number = contact_number;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }



    public  boolean checkContactNumberIsValid(String contactNumber){
        String regexStr = "^[0-9]{10}$";
       if( contactNumber.matches(regexStr)){
           return true;
       }
       else return false;
    }

    public  boolean checkPasswordIsValid(String password){
       if( password.length() < 8 || !password.matches("(?=.*[0-9]).*") || !password.matches("(?=.*[A-Z]).*")|| !password.matches("(?=.*[~!@#$%^&*()_-]).*")){
           return false;
       }

            return true;

    }

    public  boolean checkAuthenticationFormat(String authorization){
        String regexStr = "^[0-9]{10}$";
        byte[] decode = Base64.getDecoder().decode(authorization.split("Basic ")[1]);
        String decodedText = new String(decode);
        String[] decodedArray = decodedText.split(":");

        String basic = authorization.split("Basic")[1];
        if(basic.indexOf("Basic") == 0 && decodedText.contains(":") && checkContactNumberIsValid(decodedArray[0]) && checkPasswordIsValid(decodedArray[1]) ){
           return  true;
        }
        else {
            return false;
        }
    }


    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(this).hashCode();
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.MULTI_LINE_STYLE);
    }

}
