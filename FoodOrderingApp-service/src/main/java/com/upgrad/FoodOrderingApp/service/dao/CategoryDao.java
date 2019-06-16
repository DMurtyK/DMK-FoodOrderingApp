package com.upgrad.FoodOrderingApp.service.dao;

import com.upgrad.FoodOrderingApp.service.entity.AddressEntity;
import com.upgrad.FoodOrderingApp.service.entity.CategoryEntity;
//import com.upgrad.FoodOrderingApp.service.entity.PaymentEntity;
import com.upgrad.FoodOrderingApp.service.entity.CategoryItemEntity;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;
import java.util.List;

@Repository
public class CategoryDao {

    @PersistenceContext
    private EntityManager entityManager;

    public List<CategoryEntity> getAllCategories(){

        try {
            return this.entityManager.createNamedQuery("allCategories", CategoryEntity.class).getResultList();
        } catch (NoResultException nre) {
            return null;
        }
    }

    public CategoryEntity getCategoryById(String category_id){

        try {
            return entityManager.createNamedQuery("categoryById", CategoryEntity.class).setParameter("uuid", category_id).getSingleResult();
        } catch (NoResultException nre) {
            return null  ;
        }
    }

    public List<CategoryItemEntity> getItemByCategoryId(CategoryEntity categoryEntity){

        try {
            return this.entityManager.createNamedQuery("customerItemByCategoryId", CategoryItemEntity.class).setParameter("categoryEntity", categoryEntity).getResultList();
        } catch (NoResultException nre) {
            return null ;
        }
    }

}
