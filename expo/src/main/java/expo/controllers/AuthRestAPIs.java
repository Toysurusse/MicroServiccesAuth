package expo.controllers;

import expo.security.jwt.JwtProvider;
import message.request.LoginForm;
import message.request.SignUpForm;
import message.response.JwtResponse;
import message.response.ResponseMessage;
import model.Role;
import model.RoleName;
import model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import repository.RoleRepository;
import repository.UserRepository;
import services.UserService;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/back/auth/api/auth")
public class AuthRestAPIs {

	private static final Logger logger = LoggerFactory.getLogger(AuthRestAPIs.class);

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
    UserRepository userRepository;

	@Autowired
	UserService userservice;

	@Autowired
    RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtProvider jwtProvider;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest) {
		logger.info("In");
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		String jwt = jwtProvider.generateJwtToken(authentication);
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

		return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUsername(), userDetails.getAuthorities()));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpForm signUpRequest) {

		logger.info("Sign Up Init");

		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return new ResponseEntity<>(new ResponseMessage("Fail -> Username is already taken!"),
					HttpStatus.BAD_REQUEST);
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return new ResponseEntity<>(new ResponseMessage("Fail -> Email is already in use!"),
					HttpStatus.BAD_REQUEST);
		}

		// Creating user's account
		User user = new User(signUpRequest.getName(), signUpRequest.getUsername(), signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		strRoles.forEach(role -> {
			switch (role) {
			case "admin":
				Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
						.orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
				roles.add(adminRole);

				break;
			case "pm":
				Role pmRole = roleRepository.findByName(RoleName.ROLE_PM)
						.orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
				roles.add(pmRole);

				break;
			default:
				Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
						.orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
				roles.add(userRole);
			}
		});

		user.setRoles(roles);
		userRepository.save(user);

		return new ResponseEntity<>(new ResponseMessage("User registered successfully!"), HttpStatus.OK);
	}


	@PostMapping("/info")
	public ResponseEntity<?> updateUser(@Valid @RequestBody String token) {

		logger.info("Sign Info");

		// Control credentials

		jwtProvider.validateJwtToken(token);
		Optional<User> user = userservice.userByUserName(jwtProvider.getUserNameFromJwtToken(token));
		User userNotOpt = user.get();


		// Sent UserReponse
		SignUpForm signUpForm = new SignUpForm();
		signUpForm.setEmail(userNotOpt.getEmail());
		signUpForm.setName(userNotOpt.getName());
		signUpForm.setUsername(userNotOpt.getUsername());

		return new ResponseEntity<>(signUpForm, HttpStatus.OK);
	}

	@PostMapping("/signupdate")
	public ResponseEntity<?> updateUser(@Valid @RequestBody SignUpForm signUpdateRequest) {

		logger.info("Sign Update Init");

		jwtProvider.validateJwtToken(signUpdateRequest.getName());
		Optional<User> user = userservice.userByUserName(jwtProvider.getUserNameFromJwtToken(signUpdateRequest.getName()));
		User userNotOpt = user.get();

		logger.info("SignUpdate pass Control");

		// Creating user's account

		userNotOpt.setEmail(signUpdateRequest.getEmail());
		userNotOpt.setPassword(encoder.encode(signUpdateRequest.getPassword2()));
		userNotOpt.setUsername(signUpdateRequest.getUsername());

		userRepository.save(userNotOpt);

		return new ResponseEntity<>(new ResponseMessage("User registered successfully!"), HttpStatus.OK);
	}
}