package com.upgrad.FoodOrderingApp.service.entity;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.io.Serializable;

@Entity
@Table(name = "category_item")
@NamedQueries({
        @NamedQuery( name = "customerItemByCategoryId", query = "select ci from CategoryItemEntity ci where ci.categoryEntity = :categoryEntity")
        })

public class CategoryItemEntity implements Serializable {

    @Id
    @Column(name = "ID")
    @NotNull
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @ManyToOne
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JoinColumn(name = "ITEM_ID")
    @NotNull
    private ItemEntity itemEntity;

    @ManyToOne
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JoinColumn(name = "CATEGORY_ID")
    @NotNull
    private CategoryEntity categoryEntity;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public ItemEntity getItemEntity() {
        return itemEntity;
    }

    public void setItemEntity(ItemEntity itemEntity) {
        this.itemEntity = itemEntity;
    }

    public CategoryEntity getCategoryEntity() {
        return categoryEntity;
    }

    public void setCategoryEntity(CategoryEntity categoryEntity) {
        this.categoryEntity = categoryEntity;
    }
}


