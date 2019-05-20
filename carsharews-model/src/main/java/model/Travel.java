package model;

import org.hibernate.annotations.NaturalId;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.sql.Timestamp;

@Entity
@Table(name = "travels")
public class Travel {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long travel_id;

    @NotBlank
    @NaturalId
    @Size(min=3, max = 150)
    private String code;

    @NotBlank
    @Size(min=3, max = 50)
    private String travel;

    @NotNull
    @OneToOne
    private City city;

    @OneToOne
    private City cityEvent;

    @NotBlank
    @Size(min=3, max = 50)
    private String typeCar;

    private int dispo;

    private boolean active;

    @OneToOne
    private User user ;

    @ManyToOne (cascade=CascadeType.ALL)
    private Event event;

    private Timestamp beginEvent;

    private Timestamp endEvent;

    public Travel() {
    }

    public Travel(String code, @NotBlank @Size(min = 3, max = 50) String travel, @NotBlank @Size(min = 3, max = 50) String typeCar, @NotBlank int dispo, @NotBlank boolean active, User user, Event event, City city, City cityEvent, Timestamp timestamp,Timestamp timestampEnd) {
        this.code = code;
        this.travel = travel;
        this.typeCar = typeCar;
        this.dispo = dispo;
        this.active = active;
        this.user = user;
        this.event = event;
        this.city=city;
        this.cityEvent=cityEvent;
        this.beginEvent = timestamp;
        this.endEvent = timestampEnd;
    }

    public Timestamp getBeginEvent() {
        return beginEvent;
    }

    public void setBeginEvent(Timestamp beginEvent) {
        this.beginEvent = beginEvent;
    }

    public Timestamp getEndEvent() {
        return endEvent;
    }

    public void setEndEvent(Timestamp endEvent) {
        this.endEvent = endEvent;
    }

    public City getCityEvent() {
        return cityEvent;
    }

    public void setCityEvent(City cityEvent) {
        this.cityEvent = cityEvent;
    }

    public City getCity() {
        return city;
    }

    public void setCity(City city) {
        this.city = city;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getTypeCar() {
        return typeCar;
    }

    public void setTypeCar(String typeCar) {
        this.typeCar = typeCar;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public Long getTravel_id() {
        return travel_id;
    }

    public void setTravel_id(Long travel_id) {
        this.travel_id = travel_id;
    }

    public String getTravel() {
        return travel;
    }

    public void setTravel(String travel) {
        this.travel = travel;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Event getEvent() {
        return event;
    }

    public void setEvent(Event event) {
        this.event = event;
    }

    public int getDispo() {
        return dispo;
    }

    public void setDispo(int dispo) {
        this.dispo = dispo;
    }
}
