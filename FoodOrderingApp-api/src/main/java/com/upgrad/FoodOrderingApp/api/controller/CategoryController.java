package com.upgrad.FoodOrderingApp.api.controller;


import com.upgrad.FoodOrderingApp.api.model.*;
import com.upgrad.FoodOrderingApp.service.businness.CategoryService;
import com.upgrad.FoodOrderingApp.service.businness.ItemService;
import com.upgrad.FoodOrderingApp.service.entity.CategoryEntity;
import com.upgrad.FoodOrderingApp.service.entity.CategoryItemEntity;
import com.upgrad.FoodOrderingApp.service.entity.ItemEntity;
import com.upgrad.FoodOrderingApp.service.exception.CategoryNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static sun.security.krb5.Confounder.longValue;

@RestController
@CrossOrigin
@RequestMapping("/")
public class CategoryController {

    @Autowired
    private CategoryService categoryService;

    @Autowired
    private ItemService itemService;


   // Get All Categories - “/category”
    @RequestMapping(method = RequestMethod.GET, path = "/category",produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<List<CategoryListResponse>> getAllCategories(){
        List<CategoryEntity> categoryEntityList=new ArrayList<CategoryEntity>();
        categoryEntityList.addAll(categoryService.getAllCategories());

        List<CategoryListResponse> categoryListResponseList=new ArrayList<CategoryListResponse>();

        for (CategoryEntity categoryEntity : categoryEntityList) {

            CategoryListResponse categoryListResponse=new CategoryListResponse();
           categoryListResponseList.add(categoryListResponse
                    .categoryName(categoryEntity.getCategoryName())
                   .id(UUID.fromString(categoryEntity.getUuid())));
        }

        return new ResponseEntity<List<CategoryListResponse>>(categoryListResponseList, HttpStatus.OK);
    }

  //  Get Category by Id - “/category/{category_id}”
    @RequestMapping(method = RequestMethod.GET, path = "/category/{category_id}",consumes = MediaType.APPLICATION_JSON_UTF8_VALUE,produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
   public ResponseEntity<CategoryDetailsResponse> getCategoryById(@PathVariable("category_id")final String category_id) throws CategoryNotFoundException {

      // CategoryEntity categoryEntity = categoryService.categoryById( Long.parseLong(category_id));
        CategoryEntity categoryEntity = categoryService.categoryById( category_id);

       List<CategoryItemEntity> categoryItemEntity = categoryService.getItemByCategoryId(categoryEntity);

       List<CategoryDetailsResponse> categoryDetailsResponseList=new ArrayList<CategoryDetailsResponse>();


        CategoryDetailsResponse categoryDetailsResponse=new CategoryDetailsResponse();
        List<ItemEntity> itemEntityList = new ArrayList<ItemEntity>();
        itemEntityList = itemService.getAllItems();

        ItemList itemlist = new ItemList();

        for( CategoryItemEntity categoryItemEntity1 : categoryItemEntity){
            for(ItemEntity itemEntity: itemEntityList){
                if( categoryItemEntity1.getItemEntity().getId() == itemEntity.getId()){

                    itemlist.setId(UUID.fromString(itemEntity.getUuid()));
                    itemlist.setItemName(itemEntity.getItemName());
                    itemlist.setPrice(itemEntity.getPrice());
                    itemlist.setItemType(ItemList.ItemTypeEnum.fromValue(itemEntity.getType()));

                }
            }
        }
        categoryDetailsResponse.addItemListItem(itemlist);
        categoryDetailsResponse.id(UUID.fromString(categoryEntity.getUuid()))
                .categoryName(categoryEntity.getCategoryName());

        return new ResponseEntity<CategoryDetailsResponse>(categoryDetailsResponse, HttpStatus.OK);
    }






}
