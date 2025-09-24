package security_for_login_registration.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import security_for_login_registration.entity.Customer;

@Repository
public interface CustomerRepository extends JpaRepository<Customer, Integer>{

	Customer findByEmail(String email);
}