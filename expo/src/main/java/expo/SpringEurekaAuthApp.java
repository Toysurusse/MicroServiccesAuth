package expo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cloud.client.circuitbreaker.EnableCircuitBreaker;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@SpringBootApplication
@EnableEurekaClient 	// Enable eureka client.
@EnableCircuitBreaker 	// Enable circuit breakers
@EnableWebMvc
@EnableJpaRepositories(basePackages={"repository"})
@ComponentScan(basePackages = {"services", "expo.controllers", "expo.security"})
@EntityScan(basePackages={"model"})
public class SpringEurekaAuthApp {
	public static void main(String[] args) {
		SpringApplication.run(SpringEurekaAuthApp.class, args);
	}

	// Create a bean for restTemplate to call services
	@Bean
	@LoadBalanced		// Load balance between service instances running at different ports.
	public RestTemplate restTemplate() {
		return new RestTemplate();
	}
}
