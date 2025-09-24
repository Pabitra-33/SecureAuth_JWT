package security_for_login_registration.service;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import security_for_login_registration.entity.Customer;
import security_for_login_registration.repository.CustomerRepository;

@Service
public class CustomerService implements UserDetailsService {

	@Autowired
	private CustomerRepository customerRepo;

	@Autowired
	private PasswordEncoder passwordEncoder; // fixed (use interface)

	// Save new customer with encoded password
	public boolean saveCustomer(Customer customer) {

		customer.setPswd(passwordEncoder.encode(customer.getPswd())); // encode before saving
		Customer saved = customerRepo.save(customer);
		return saved.getCid() != null;

	}

	// Load user for authentication
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Customer customer = customerRepo.findByEmail(username);

		if (customer == null) {
			throw new UsernameNotFoundException("User not found with email: " + username);
		}

		// right now roles = emptyList(), can add ROLE_USER, ROLE_ADMIN later
		return new User(customer.getEmail(), customer.getPswd(), Collections.emptyList());
	}
}