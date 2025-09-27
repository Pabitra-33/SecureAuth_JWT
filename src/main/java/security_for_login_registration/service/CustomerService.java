package security_for_login_registration.service;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import security_for_login_registration.entity.Customer;
import security_for_login_registration.repository.CustomerRepository;

@Service
public class CustomerService implements UserDetailsService {

	@Autowired
	private BCryptPasswordEncoder pswdEncoder;

	@Autowired
	private CustomerRepository customerRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Customer customer = customerRepository.findByEmail(username);

		return new User(customer.getEmail(), customer.getPswd(), Collections.emptyList());
        //assigning user credentials for user object email,pswd, roles
	}

	public boolean saveCustomer(Customer customer) {
		String pswd = pswdEncoder.encode(customer.getPswd());
		customer.setPswd(pswd);
		Customer save = customerRepository.save(customer);

		return save.getCid() != null;
	}

}