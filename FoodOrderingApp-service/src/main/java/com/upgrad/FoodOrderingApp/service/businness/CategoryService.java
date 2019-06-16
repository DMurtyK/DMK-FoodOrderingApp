package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.CategoryDao;
//import com.upgrad.FoodOrderingApp.service.dao.PaymentDao;
import com.upgrad.FoodOrderingApp.service.entity.CategoryEntity;
//import com.upgrad.FoodOrderingApp.service.entity.PaymentEntity;
import com.upgrad.FoodOrderingApp.service.entity.CategoryItemEntity;
import com.upgrad.FoodOrderingApp.service.exception.CategoryNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class CategoryService {

    @Autowired
    private CategoryDao categoryDao;

    @Transactional(propagation = Propagation.REQUIRED)
    public List<CategoryEntity> getAllCategories() {

        return categoryDao.getAllCategories();
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public CategoryEntity categoryById( String category_id) throws CategoryNotFoundException {



       // String category_idAsString = Long.toString(category_id);

        if(category_id == null) {
            throw new CategoryNotFoundException("CNF-001", "Category id field should not be empty");
        }
        CategoryEntity categoryEntity = categoryDao.getCategoryById(category_id);
        if(categoryEntity == null){
            throw new CategoryNotFoundException("CNF-002", "No category by this id");
        }else{
            return categoryEntity;
        }
    }

    @Transactional
    public List<CategoryItemEntity> getItemByCategoryId(CategoryEntity categoryEntity) {


            return  categoryDao.getItemByCategoryId(categoryEntity);

    }


}