package in.rbihub.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;
import org.springframework.beans.factory.annotation.Value;
import io.micrometer.core.aop.TimedAspect;
import io.micrometer.core.instrument.MeterRegistry;

//import javax.validation.constraints.NotBlank;
@ConfigurationProperties(prefix = "app")
@Configuration
@Data
@Validated
public class ApplicationConfig {

    @Value("${app.secretkey}")
    private String secretkey;

    @Value("${app.privatekey}")
    private String privatekey;


    @Value("${app.publickeypath}")
    private String publickeypath;

    @Value("${app.sigpassword}")
    private String sigpassword;

    public String getSecretkey() {
        return secretkey;
    }

    public String getPrivatekey() {
        return privatekey;
    }

    public String getPublickeypath() {
        return publickeypath;
    }

    public String getSigpassword() {
        return sigpassword;
    }

    @Bean
    public TimedAspect timedAspect(MeterRegistry registry) {
        return new TimedAspect(registry);
    }

}
