package model;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Entity
@Table(name = "passager")
public class Passager {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long passager_id;

    @Size(max = 1000)
    private String userInfo;

    @OneToOne
    private User user;

    @ManyToOne (cascade=CascadeType.ALL)
    private Travel travel;

    public Passager() {
    }

    public Passager(@Size(max = 1000) String userInfo, User user, Travel travel) {
        this.userInfo = userInfo;
        this.user = user;
        this.travel = travel;
    }

    public Long getPassager_id() {
        return passager_id;
    }

    public void setPassager_id(Long passager_id) {
        this.passager_id = passager_id;
    }

    public String getUserInfo() {
        return userInfo;
    }

    public void setUserInfo(String userInfo) {
        this.userInfo = userInfo;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Travel getTravel() {
        return travel;
    }

    public void setTravel(Travel travel) {
        this.travel = travel;
    }
}
