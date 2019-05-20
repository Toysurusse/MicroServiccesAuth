package model;


import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.NaturalId;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.sql.Date;
import java.sql.Timestamp;


@Entity
@Table(name = "events")
public class Event {

    @Id
    @GeneratedValue(strategy=GenerationType.SEQUENCE, generator = "book_generator")
    @SequenceGenerator(name="book_generator", sequenceName = "book_seq", initialValue = 10, allocationSize=50)
    private Long event_id;

    @NotBlank
    @Size(min = 3, max = 50)
    private String nameEvent;

    private Timestamp beginEvent;

    private Timestamp endEvent;

    @NotBlank
    @Size(max = 50)
    private String voyage;

    private boolean active;

    private boolean delete;

    @Column(name = "created_at")
    @CreationTimestamp
    private Date createdAt;

    @Column(name = "update_at")
    @UpdateTimestamp
    private Date updateAt;

    @NotBlank
    @Size(min = 3, max = 100)
    private String type;

    @NotNull
    @OneToOne
    private City city;

    @OneToOne
    private User user;

    public Event() {
    }

    public Event(@NotBlank @Size(min = 3, max = 50) String nameEvent, @NotBlank @Size(max = 50) String voyage, @NotBlank boolean active,
                 @NotBlank boolean delete, @NotBlank @Size(min = 3, max = 100) String type, User user, City city, Timestamp timestamp,Timestamp timestampEnd) {
        this.nameEvent = nameEvent;
        this.voyage = voyage;
        this.active = active;
        this.delete = delete;
        this.type = type;
        this.user = user;
        this.city = city;
        this.beginEvent = timestamp;
        this.endEvent = timestampEnd;
    }



    public Timestamp getEndEvent() {
        return endEvent;
    }

    public void setEndEvent(Timestamp endEvent) {
        this.endEvent = endEvent;
    }

    public Timestamp getBeginEvent() {
        return beginEvent;
    }

    public void setBeginEvent(Timestamp beginEvent) {
        this.beginEvent = beginEvent;
    }

    public City getCity() {
        return city;
    }

    public void setCity(City city) {
        this.city = city;
    }

    public Long getEvent_id() {
        return event_id;
    }

    public void setEvent_id(Long event_id) {
        this.event_id = event_id;
    }

    public String getNameEvent() {
        return nameEvent;
    }

    public void setNameEvent(String nameEvent) {
        this.nameEvent = nameEvent;
    }

    public String getVoyage() {
        return voyage;
    }

    public void setVoyage(String voyage) {
        this.voyage = voyage;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public boolean isDelete() {
        return delete;
    }

    public void setDelete(boolean delete) {
        this.delete = delete;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
