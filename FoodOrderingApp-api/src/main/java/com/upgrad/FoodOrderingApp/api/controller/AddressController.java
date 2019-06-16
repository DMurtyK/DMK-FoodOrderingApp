package com.upgrad.FoodOrderingApp.api.controller;


import com.upgrad.FoodOrderingApp.api.model.*;
import com.upgrad.FoodOrderingApp.service.businness.AddressService;
import com.upgrad.FoodOrderingApp.service.businness.SignupCustomerBusinessService;
import com.upgrad.FoodOrderingApp.service.entity.AddressEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAddressEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.entity.StateEntity;
import com.upgrad.FoodOrderingApp.service.exception.AddressNotFoundException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SaveAddressException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.awt.*;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.UUID;

@RestController
@CrossOrigin
@RequestMapping("/")
public class AddressController {


    @Autowired
    private SignupCustomerBusinessService customerService;

    @Autowired
    private AddressService addressService;


@RequestMapping(method = RequestMethod.POST,path ="/address",consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE )
    public ResponseEntity<SaveAddressResponse> saveAddress(@RequestBody(required = false) final SaveAddressRequest saveAddressRequest,@RequestHeader("accessToken") final String accessToken) throws AuthorizationFailedException, AddressNotFoundException, SaveAddressException {


    String [] bearerToken = accessToken.split("Bearer ");
    final CustomerEntity customerEntity = customerService.getCustomer(bearerToken[1]);
    final StateEntity stateEntity = addressService.getStateByUUID(saveAddressRequest.getStateUuid());
    final AddressEntity addressEntity= new AddressEntity();

    addressEntity.setUuid(UUID.randomUUID().toString());
    addressEntity.setFlatBuilNumber(saveAddressRequest.getFlatBuildingName());
    addressEntity.setLocality(saveAddressRequest.getLocality());
    addressEntity.setCity(saveAddressRequest.getCity());
    addressEntity.setPinCode(saveAddressRequest.getPincode());
    addressEntity.setState(stateEntity);
    addressEntity.setActive(1);

    final AddressEntity savedAddressEntity = addressService.saveAddress(addressEntity,stateEntity);

    final CustomerAddressEntity customerAddressEntity=new CustomerAddressEntity();
    customerAddressEntity.setAddress(savedAddressEntity);
    customerAddressEntity.setCustomer(customerEntity);
    addressService.createCustomerAddress(customerAddressEntity);

    SaveAddressResponse saveAddressResponse = new SaveAddressResponse()
            .id(savedAddressEntity.getUuid())
            .status("ADDRESS SUCCESSFULLY REGISTERED");
    return new ResponseEntity<SaveAddressResponse>(saveAddressResponse, HttpStatus.CREATED);





}



/*

    @RequestMapping(method = RequestMethod.DELETE, path = "/address/{address_id}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<DeleteAddressResponse> deleteAddress(@PathVariable("address_id") final String address_id,
                                                               @RequestHeader("authorization") final String accessToken)
            throws AuthorizationFailedException, AddressNotFoundException {
       // AddressEntity addressEntity = null;
        DeleteAddressResponse deleteAddressResponse = null;

        //Bearer Authorization
        String[] bearerToken = accessToken.split("Bearer ");

        final CustomerEntity customerEntity = customerService.getCustomer(bearerToken[1]);

        if(customerEntity!= null && address_id == null) {


             AddressEntity addressEntity = addressService.deleteAddress(address_id, bearerToken[1]);

            deleteAddressResponse = new DeleteAddressResponse().id((UUID.fromString(addressEntity.getUuid()))).
                    status("ADDRESS DELETED SUCCESSFULLY");
            return new ResponseEntity<DeleteAddressResponse>(deleteAddressResponse, HttpStatus.OK);
        }
        return new ResponseEntity<DeleteAddressResponse>(deleteAddressResponse, HttpStatus.OK);

    }


    //deleteAddress endpoint deletes the address of a particular customer
    @RequestMapping(method= RequestMethod.DELETE,path="/address/{address_id}",produces= MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<DeleteAddressResponse> deleteAddress(@PathVariable("address_id") final String addressUuid,
                                                               @RequestHeader("accessToken") final String accessToken) throws AuthorizationFailedException, AddressNotFoundException {

        String [] bearerToken = accessToken.split("Bearer ");
        final CustomerEntity signedinCustomerEntity = customerService.getCustomer(bearerToken[1]);
        final AddressEntity addressEntityToDelete=addressService.getAddressByAddressUuid(addressUuid);
        final CustomerAddressEntity customerAddressEntity=addressService.getCustomerIdByAddressId(addressEntityToDelete.getId());
        final CustomerEntity ownerofAddressEntity=customerAddressEntity.getCustomer();
        final String Uuid = addressService.deleteAddress(addressEntityToDelete,signedinCustomerEntity,ownerofAddressEntity);

        DeleteAddressResponse deleteAddressResponse = new DeleteAddressResponse()
                .id(UUID.fromString(Uuid))
                .status("ADDRESS DELETED SUCCESSFULLY");
        return new ResponseEntity<DeleteAddressResponse>(deleteAddressResponse, HttpStatus.OK);
    }


    /* WORK IN PROGRESS */
    //getallsavedaddresses endpoint retrieves all the addresses of a valid customer present in the database
    /*
    @RequestMapping(method = RequestMethod.GET, path = "/address/customer",  produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<AddressListResponse> getallsavedaddresses(@RequestHeader("accessToken") final String accessToken) throws AuthorizationFailedException  {

        String [] bearerToken = accessToken.split("Bearer ");
        //authorizationBusinessService.verifyAuthToken(bearerToken[1]);

        List<AddressEntity> addressEntityList=new ArrayList<AddressEntity>();
        addressEntityList.addAll(addressService.getAllSavedAddresses(accessToken));
        AddressListResponse addressListResponse=new AddressListResponse();

        for (AddressEntity addressEntity : addressEntityList) {

            AddressList addressList =new AddressList();
            addressList.setId(UUID.fromString(addressEntity.getUuid()));
            //statesList.setStateName(stateEntity.getStateName());
            addressListResponse.addAddressesItem(addressList);
        }


        return new ResponseEntity<AddressListResponse>(addressListResponse,HttpStatus.OK);
    }

    */

/*
    //getallstates endpoint retrieves all the states present in the database
    @RequestMapping(method = RequestMethod.GET, path = "/states",  produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<StatesListResponse> getallstates(){


        List<StateEntity> stateEntityList=new ArrayList<StateEntity>();
        stateEntityList.addAll(addressService.getAllStates());
        StatesListResponse statesListResponse=new StatesListResponse();

        for (StateEntity stateEntity : stateEntityList) {

            // List<StatesList> statesListList=new ArrayList<StatesList>();
            StatesList statesList =new StatesList();
            statesList.setId(UUID.fromString(stateEntity.getUuid()));
            statesList.setStateName(stateEntity.getStateName());
            statesListResponse.addStatesItem(statesList);
        }


        return new ResponseEntity<StatesListResponse>(statesListResponse,HttpStatus.OK);
    }
    */

}



