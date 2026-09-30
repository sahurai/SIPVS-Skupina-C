package sk.fiit.sipvs;

import java.time.LocalDate;
import java.util.List;

public record Protokol(
        String univerzitneId,
        String meno,
        String priezvisko,
        LocalDate datumNarodenia,
        String statnaPrislusnost,
        String fakulta,
        int rocnik,
        String telefon,
        String email,
        Fotografia fotografia,
        String zakonnyZastupca,
        Adresa adresa,
        List<Spotrebic> spotrebice,
        boolean suhlas,
        LocalDate datumVyplnenia) {

    public record Adresa(String ulica, String cislo, String mesto, String psc, String stat) {
    }

    public record Spotrebic(String typ, String znacka, String serioveCislo, int prikon) {
    }

    public record Fotografia(String typ, String data) {
    }
}
