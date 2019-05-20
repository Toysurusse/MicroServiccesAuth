package services;

import model.User;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Service;
import repository.UserRepository;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRepository;

    @Override
    public void add(User user) {
    }

    @Override
    public Optional<User> userByUserName (String userName){
    return userRepository.findByUsername(userName);
    }
}
