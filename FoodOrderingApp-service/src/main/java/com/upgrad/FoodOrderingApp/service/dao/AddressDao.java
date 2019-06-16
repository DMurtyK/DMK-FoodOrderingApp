package com.upgrad.FoodOrderingApp.service.dao;

import com.upgrad.FoodOrderingApp.service.entity.AddressEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAddressEntity;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;
import java.util.List;

@Repository
public class AddressDao {

    @PersistenceContext
    private EntityManager entityManager;

    //saves the customer address information of the created address record  in the database
    public AddressEntity createAddress(AddressEntity addressEntity) {
        this.entityManager.persist(addressEntity);
        return addressEntity;
    }
    //creates a customerAddress record
    public CustomerAddressEntity createCustomerAddress(CustomerAddressEntity customerAddressEntity) {
        this.entityManager.persist(customerAddressEntity);
        return customerAddressEntity;
    }

    public AddressEntity getAddressByAddressUuid(String StateUuid) {
        try {
            return (AddressEntity)this.entityManager.createNamedQuery("addressByAddressUuid", AddressEntity.class).setParameter("uuid", StateUuid).getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }
    //This method needs testing n editing
    public List<AddressEntity> getAllSavedAddresses(){

        try {
            return this.entityManager.createNamedQuery("allSavedAddresses", AddressEntity.class).getResultList();
        } catch (NoResultException nre) {
            return null;
        }
    }

    public AddressEntity  deleteAddress(AddressEntity addressEntity ) {
        entityManager.remove(addressEntity);
        return addressEntity;
    }
}