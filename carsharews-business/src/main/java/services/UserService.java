package services;

import model.User;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.Optional;

public interface UserService {
    void add(User user);
    Optional<User> userByUserName (String userName);
}
