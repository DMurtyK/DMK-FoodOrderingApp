package com.upgrad.FoodOrderingApp.service.businness;



import com.upgrad.FoodOrderingApp.service.dao.AddressDao;
import com.upgrad.FoodOrderingApp.service.dao.CustomerDao;
import com.upgrad.FoodOrderingApp.service.dao.StateDao;
import com.upgrad.FoodOrderingApp.service.entity.*;
import com.upgrad.FoodOrderingApp.service.exception.AddressNotFoundException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SaveAddressException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AddressService {

    //Respective Data access object has been autowired to access the method defined in respective Dao
    @Autowired
    private CustomerDao customerDao;
    @Autowired
    private AddressDao addressDao;
    @Autowired
    private StateDao stateDao;

    @Transactional(propagation = Propagation.REQUIRED)
    public StateEntity getStateByUUID(final String StateUuid) throws AddressNotFoundException,SaveAddressException {
        StateEntity stateEntity = stateDao.getStateByStateUuid(StateUuid);
        if(StateUuid.isEmpty()){
            throw new SaveAddressException("SAR-001", "No field can be empty");
        }
        if(stateEntity == null){
            throw new AddressNotFoundException("ANF-002", "No state by this id");
        } else {
            return stateEntity;
        }
    }


    @Transactional(propagation = Propagation.REQUIRED)
    public AddressEntity saveAddress(final AddressEntity addressEntity, final StateEntity stateEntity) throws SaveAddressException {

        String pinCodeRegex = "^[0-9]{6}$";

        if (addressEntity.getFlatBuilNumber().isEmpty() || addressEntity.getLocality().isEmpty() || addressEntity.getCity().isEmpty() || addressEntity.getPinCode().isEmpty() || addressEntity.getUuid().isEmpty()) {
            throw new SaveAddressException("SAR-001", "No field can be empty");
        } else if (!addressEntity.getPinCode().matches(pinCodeRegex)) {
            throw new SaveAddressException("SAR-002", "Invalid pincode");
        } else {
            return addressDao.createAddress(addressEntity);
        }
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerAddressEntity createCustomerAddress(final CustomerAddressEntity customerAddressEntity) {
        return addressDao.createCustomerAddress(customerAddressEntity);
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public List<AddressEntity> getAllSavedAddresses(final String accessToken) {
        CustomerAuthTokenEntity customerAuthEntity = customerDao.getCustomerAuthToken(accessToken);

        return addressDao.getAllSavedAddresses();
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public List<StateEntity> getAllStates() {
        return stateDao.getAllStates();
    }

    @javax.transaction.Transactional
    public AddressEntity deleteAddress(final String questionId, final String accessToken)
            throws AuthorizationFailedException, AddressNotFoundException {

        CustomerAuthTokenEntity userAuthTokenEntity = customerDao.getCustomerAuthToken(accessToken);

        AddressEntity addressEntity=addressDao.getAddressByAddressUuid(questionId);



        return addressDao.deleteAddress(addressEntity);
    }
}
