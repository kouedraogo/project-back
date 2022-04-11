package com.abelardo.isika.springbootsecurityjwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.abelardo.isika.springbootsecurityjwt.models.ERole;
import com.abelardo.isika.springbootsecurityjwt.models.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
	Optional<Role> findByName(ERole name);
}
