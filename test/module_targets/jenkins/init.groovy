import groovy.json.JsonSlurper
import hudson.security.AuthorizationStrategy
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import hudson.security.SecurityRealm
import hudson.security.csrf.DefaultCrumbIssuer
import jenkins.install.InstallState
import jenkins.model.Jenkins
import jenkins.security.ApiTokenProperty

def instance = Jenkins.get()
def realm = new HudsonPrivateSecurityRealm(false)
def account = realm.createAccount('module_target', 'module-target-password')
def tokens = account.getProperty(ApiTokenProperty.class).tokenStore
tokens.revokeAllTokens()
// Public fixture token, using the native API supported by these pinned releases.
tokens.addFixedNewToken('module-target', '1100000000000000000000000000000000')
account.save()

if (System.getenv('LAB_OPEN') == 'true') {
    instance.setSecurityRealm(SecurityRealm.NO_AUTHENTICATION)
    instance.setAuthorizationStrategy(AuthorizationStrategy.UNSECURED)
} else {
    instance.setSecurityRealm(realm)
    def authorization = new FullControlOnceLoggedInAuthorizationStrategy()
    authorization.setAllowAnonymousRead(false)
    instance.setAuthorizationStrategy(authorization)
}
instance.setCrumbIssuer(new DefaultCrumbIssuer(false))
instance.setNumExecutors(0)
instance.setSlaveAgentPort(-1)
instance.setInstallState(InstallState.INITIAL_SETUP_COMPLETED)
instance.save()

def fixtures = new JsonSlurper().parse(new File('/opt/module-target-fixtures.json'))
fixtures.each { name, fixture ->
    if (fixture.content != null) {
        def file = new File(fixture.path)
        file.parentFile.mkdirs()
        file.setText(fixture.content, 'UTF-8')
    }
}
new File(instance.rootDir, 'module-target-ready').text = 'ready\n'
