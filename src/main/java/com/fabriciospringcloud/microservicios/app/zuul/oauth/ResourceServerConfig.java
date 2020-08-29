package com.fabriciospringcloud.microservicios.app.zuul.oauth;

import java.util.Arrays;

//import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
//import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@RefreshScope
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

	@Value("${config.security.oauth.jwt.key}")
	private String jwtKey;
	
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.tokenStore(tokenStore());
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/api/security/oauth/**",
				     "/api/usuarios/uploads/img/{id}",
				     "/api/reportes/pdf/{id}",
				     "/api/reportes/excel/{id}",
				     "/api/usuarios",
                     "/api/roles",
                     "/api/auditoria",
				     "/api/usuarios/pagina").permitAll()
		.antMatchers(HttpMethod.GET, "/api/usuarios/filtrar/{params}",
									 "/api/usuarios/uploads/img/{id}",
									 "/api/usuarios/listar").hasAnyRole("ADMIN", "USER")
		
		.antMatchers(HttpMethod.GET, "/api/usuarios/{id}").hasRole("ADMIN")
		
		.antMatchers(HttpMethod.POST, "/api/usuarios", 
				  					  "/api/usuarios/crear-usuario",
				  					  "/api/usuarios/crear-con-foto").hasRole("ADMIN")
	
		.antMatchers(HttpMethod.PUT, "/api/usuarios/{id}",
									 "/api/usuarios/editar-con-foto/{id}",
									 "/api/usuarios/{id}/activar",
									 "/api/usuarios/{id}/asignar-roles",
									 "/api/usuarios/{id}/password",
									 "/api/usuarios/{id}/eliminar-role").hasRole("ADMIN")
		
		//Rutas no especificadas con prefijo /api/usuarios/ solo para role ADMIN
		.antMatchers("/api/usuarios/**","/api/roles/**").hasRole("ADMIN")
		//Rutas no especificadas requiere autenticacion
		.anyRequest().authenticated()
		.and().cors()
		.configurationSource(corsConfigurationSource());
    }	

	
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration corsConfig = new CorsConfiguration();
		corsConfig.setAllowedOrigins(Arrays.asList("http://localhost:4200", "*"));
		corsConfig.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "OPTIONS"));
		corsConfig.setAllowCredentials(true);
		corsConfig.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", corsConfig);

		return source;
	}
	
	@Bean
	public FilterRegistrationBean<CorsFilter> corsFilter(){
		FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<CorsFilter>(new CorsFilter(corsConfigurationSource()));
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return bean;
	}	

	@Bean
	public JwtTokenStore tokenStore() {
		return new JwtTokenStore(accessTokenConverter());
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
//		tokenConverter.setSigningKey(env.getProperty("config.security.oauth.jwt.key"));
		tokenConverter.setSigningKey(jwtKey);
		// tokenConverter.setSigningKey("algun_codigo_secreto_aeiou");
		return tokenConverter;
	}

}