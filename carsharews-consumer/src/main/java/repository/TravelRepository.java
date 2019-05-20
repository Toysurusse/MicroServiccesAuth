package repository;

import model.Event;
import model.Travel;
import model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TravelRepository extends JpaRepository<Travel, Long> {
    List<Travel> findAllByEvent(Event event);
    List<Travel> findAllByUser(User user);
    Travel findByCode(String name);
}
