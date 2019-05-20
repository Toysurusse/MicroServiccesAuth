package model;


import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.sql.Timestamp;

@Entity
@Table(name = "cities")
public class City {

    @Id
    private Long villeId;

    private int departementId;

    @NotBlank
    @Size(max = 255)
    private String ville;

    @NotBlank
    @Size(min=1, max = 50)
    private String slug;

    @NotBlank
    @Size(min=1, max = 255)
    private String codepostal;

    @NotBlank
    @Size(min=1, max = 8)
    private String codeinsee;

    @NotBlank
    @Size(min=1, max = 20)
    private String latitude;

    @NotBlank
    @Size(min=1, max = 20)
    private String longitude;

    public Long getVilleId() {
        return villeId;
    }

    public void setVilleId(Long villeId) {
        this.villeId = villeId;
    }

    public int getDepartementId() {
        return departementId;
    }

    public void setDepartementId(int departementId) {
        this.departementId = departementId;
    }

    public String getVille() {
        return ville;
    }

    public void setVille(String ville) {
        this.ville = ville;
    }

    public String getSlug() {
        return slug;
    }

    public void setSlug(String slug) {
        this.slug = slug;
    }

    public String getCodepostal() {
        return codepostal;
    }

    public void setCodepostal(String codepostal) {
        this.codepostal = codepostal;
    }

    public String getCodeinsee() {
        return codeinsee;
    }

    public void setCodeinsee(String codeinsee) {
        this.codeinsee = codeinsee;
    }

    public String getLatitude() {
        return latitude;
    }

    public void setLatitude(String latitude) {
        this.latitude = latitude;
    }

    public String getLongitude() {
        return longitude;
    }

    public void setLongitude(String longitude) {
        this.longitude = longitude;
    }
}
