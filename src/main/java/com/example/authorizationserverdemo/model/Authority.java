package com.example.authorizationserverdemo.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;

@Entity
@Table(name="authority")
public class Authority implements GrantedAuthority {

    private static final long serialVersionUID = 1L;

    @Id
    @Column(name="id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "user_type")
    @Enumerated(EnumType.STRING)
    private UserType userType;

    public Authority(UserType userType) {
        this.userType = userType;
    }

    public Authority() {

    }

    @Override
    public String getAuthority() {
        return userType.toString();
    }

    public void setUserType(UserType type) {
        this.userType = type;
    }

    @JsonIgnore
    public String getUserType() {
        return userType.toString();
    }

    @JsonIgnore
    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

}

