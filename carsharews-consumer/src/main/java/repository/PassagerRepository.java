package repository;


import model.Passager;
import model.Role;
import model.Travel;
import model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PassagerRepository extends JpaRepository<Passager, Long> {
    List<Passager> findPassagersByTravel (Travel travel);
    @Query(
            value = "SELECT FROM public.passager COUNT(passager_id) WHERE travel_travel_id=1;",
            nativeQuery = true)
    int findPassenger();
}
