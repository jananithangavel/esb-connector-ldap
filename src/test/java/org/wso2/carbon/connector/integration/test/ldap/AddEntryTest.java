package org.wso2.carbon.connector.integration.test.ldap;



import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.DN;
import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMDocument;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseException;
import org.apache.synapse.config.SynapseConfiguration;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2SynapseEnvironment;
import org.apache.synapse.mediators.template.TemplateContext;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.connector.ldap.AddEntry;
import org.wso2.carbon.connector.ldap.Init;
import org.wso2.carbon.connector.ldap.LDAPConstants;
import scala.collection.generic.BitOperations;


import javax.naming.Context;
import javax.naming.directory.*;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.StringReader;
import java.net.ConnectException;
import java.util.*;

public class AddEntryTest {

    private AddEntry addEntry;
    private Init init;
    private TemplateContext templateContext;
    MessageContext messageContext;
    Stack functionStack;

    private String userBase = null;
    private String testUserId = null;
    private String providerUrl = null;
    private String securityPrincipal = null;
    private String securityCredentials = null;
    private String baseDN = null;
    private int ldapPort = 0;
    private boolean useEmbeddedLDAP = true;

    private InMemoryDirectoryServer ldapServer;

    @BeforeMethod
    public void setUp() throws Exception {
        addEntry = new AddEntry();
        init =new Init();
        initializeProperties();
        if (useEmbeddedLDAP) {
            initializeEmbeddedLDAPServer();
        }
        org.apache.axis2.context.MessageContext mc =
                new org.apache.axis2.context.MessageContext();
        SynapseConfiguration config = new SynapseConfiguration();
        SynapseEnvironment env = new Axis2SynapseEnvironment(config);
        messageContext = new Axis2MessageContext(mc, config, env);
        org.apache.axiom.soap.SOAPEnvelope envelope =
                OMAbstractFactory.getSOAP11Factory().getDefaultEnvelope();
        OMDocument omDoc =
                OMAbstractFactory.getSOAP11Factory().createOMDocument();
        omDoc.addChild(envelope);
        envelope.getBody().addChild(createOMElement("<a>test</a>"));
        messageContext.setEnvelope(envelope);
        messageContext.setProperty(LDAPConstants.SECURE_CONNECTION,"false");
        messageContext.setProperty(LDAPConstants.DISABLE_SSL_CERT_CHECKING, "false");
        templateContext = new TemplateContext("authenticate", null);
        templateContext.getMappedValues().put(LDAPConstants.PROVIDER_URL,"ldap://localhost:10389/");
        templateContext.getMappedValues().put(LDAPConstants.OBJECT_CLASS,"inetOrgPerson");
        templateContext.getMappedValues().put(LDAPConstants.SECURITY_PRINCIPAL,"cn=admin,dc=wso2,dc=com");
        templateContext.getMappedValues().put(LDAPConstants.SECURITY_CREDENTIALS,"19902");
        templateContext.getMappedValues().put(LDAPConstants.ATTRIBUTES,"{\n" +
                "      \"mail\": \"testDim1s22sc@wso2.com\",\n" +
                "      \"userPassword\": \"12345\",\n" +
                "      \"sn\": \"dim\",\n" +
                "      \"cn\": \"dim\"\n" +
                "    }");
        templateContext.getMappedValues().put(LDAPConstants.DN,"uid=john004,ou=People,dc=wso2,dc=com");
        functionStack = new Stack();
    }

    private void initializeProperties() {
        userBase = "ou=People,dc=wso2,dc=com";
        testUserId = "john004";
        providerUrl = "ldap://localhost:10389/";
        securityPrincipal = "cn=admin,dc=wso2,dc=com";
        securityCredentials = "19902";
        baseDN = "dc=wso2,dc=com";
        ldapPort = 10389;
        useEmbeddedLDAP = true;
    }

    @Test
    public void testAddEntry() throws Exception {
        try {
            functionStack.push(templateContext);
            messageContext.setProperty("_SYNAPSE_FUNCTION_STACK", functionStack);
            init.connect(messageContext);
            addEntry.connect(messageContext);
            Assert.assertEquals((messageContext.getEnvelope().getBody().getFirstElement()).getFirstElement().getText(), "Success");
        } finally {
            deleteSampleEntry();
        }
    }

    @Test
    public void testAddEntryWithMissingDn() throws Exception{
        templateContext.getMappedValues().put(LDAPConstants.DN,"");
        Stack functionStack = new Stack();
        functionStack.push(templateContext);
        messageContext.setProperty("_SYNAPSE_FUNCTION_STACK", functionStack);
        init.connect(messageContext);
        try {
            addEntry.connect(messageContext);
        }catch (SynapseException e)
        {
            String Message="[LDAP: error code 68 - Unable to add an entry with the null DN.]";
            OMElement error = messageContext.getEnvelope().getBody().getFirstElement();
            Assert.assertEquals(((OMElement) (error.getChildrenWithLocalName("errorMessage")).next()).getText(), Message);
            Assert.assertEquals(((OMElement) (error.getChildrenWithLocalName("errorCode")).next()).getText(),
                    Integer.toString(LDAPConstants.ErrorConstants.ADD_ENTRY_ERROR ));
        }
    }

    @Test
    public void testAddEntryWithWrongUserBase() throws Exception {
        templateContext.getMappedValues().put(LDAPConstants.DN,"uid=john004,ou=example,dc=example");
        Stack functionStack = new Stack();
        functionStack.push(templateContext);
        messageContext.setProperty("_SYNAPSE_FUNCTION_STACK", functionStack);
        init.connect(messageContext);
        try {
            addEntry.connect(messageContext);
        }catch (SynapseException e)
        {
            //String a= LDAPConstants.ErrorConstants.ADD_ENTRY_ERROR ;
            String Message="[LDAP: error code 32 - Unable to add entry 'uid=john004,ou=example,dc=example' " +
                    "because its parent entry 'ou=example,dc=example' does not exist in the server.]";
            OMElement error = messageContext.getEnvelope().getBody().getFirstElement();
            Assert.assertEquals(((OMElement) (error.getChildrenWithLocalName("errorMessage")).next()).getText(), Message);
            Assert.assertEquals(((OMElement) (error.getChildrenWithLocalName("errorCode")).next()).getText(),
                    Integer.toString(LDAPConstants.ErrorConstants.ADD_ENTRY_ERROR ));

        }
    }

    @Test
    public void testAddEntryWithWrongObjectClass() throws Exception {
        templateContext.getMappedValues().put(LDAPConstants.OBJECT_CLASS,"wrongObjectClass");
        functionStack.push(templateContext);
        messageContext.setProperty("_SYNAPSE_FUNCTION_STACK", functionStack);
        init.connect(messageContext);
        try {
            addEntry.connect(messageContext);
        }catch (SynapseException e)
        {
            String Message="[LDAP: error code 65 - Unable to add entry 'uid=john004,ou=People,dc=wso2,dc=com' " +
                    "because it violates the provided schema:  The entry contains object class wrongObjectClass which" +
                    " is not defined in the schema.  The entry contains attribute objectClass which is not allowed by " +
                    "its object classes and/or DIT content rule.  The entry contains attribute mail which is not" +
                    " allowed by its object classes and/or DIT content rule.  The entry contains attribute uid which" +
                    " is not allowed by its object classes and/or DIT content rule.  The entry contains attribute " +
                    "userPassword which is not allowed by its object classes and/or DIT content rule.  " +
                    "The entry contains attribute sn which is not allowed by its object classes and/or DIT content rule." +
                    "  The entry contains attribute cn which is not allowed by its object classes and/or DIT content " +
                    "rule.  The entry's RDN contains attribute uid which is not allowed to be included in the entry.]";
            OMElement error = messageContext.getEnvelope().getBody().getFirstElement();
            Assert.assertEquals(((OMElement) (error.getChildrenWithLocalName("errorMessage")).next()).getText(), Message);
            Assert.assertEquals(((OMElement) (error.getChildrenWithLocalName("errorCode")).next()).getText(),
                    Integer.toString(LDAPConstants.ErrorConstants.ADD_ENTRY_ERROR ));
        }
    }

    @Test
    public void testAddEntryWithoutMandatoryAttributes() throws Exception {
        templateContext.getMappedValues().put(LDAPConstants.ATTRIBUTES,"{\n" +
                "      \"mail\": \"testDim1s22sc@wso2.com\",\n" +
                "      \"userPassword\": \"12345\",\n" +
                "      \"sn\": \"dim\",\n" +
                "    }");
        Stack functionStack = new Stack();
        functionStack.push(templateContext);
        messageContext.setProperty("_SYNAPSE_FUNCTION_STACK", functionStack);
        init.connect(messageContext);
        try {
            addEntry.connect(messageContext);
        }catch (SynapseException e)
        {
            String Message="[LDAP: error code 65 - Unable to add entry 'uid=john004,ou=People,dc=wso2,dc=com'" +
                    " because it violates the provided schema:  The entry is missing required attribute cn.]";
            OMElement error = messageContext.getEnvelope().getBody().getFirstElement();
            Assert.assertEquals(((OMElement) (error.getChildrenWithLocalName("errorMessage")).next()).getText(), Message);
            Assert.assertEquals(((OMElement) (error.getChildrenWithLocalName("errorCode")).next()).getText(),
                    Integer.toString(LDAPConstants.ErrorConstants.ADD_ENTRY_ERROR ));
        }
        deleteSampleEntry();
    }

    private void initializeEmbeddedLDAPServer() throws Exception {
        InMemoryListenerConfig inMemoryListenerConfig =
                InMemoryListenerConfig.createLDAPConfig("default", ldapPort);
        InMemoryDirectoryServerConfig directoryServerConfig =
                new InMemoryDirectoryServerConfig(new DN(baseDN));
        directoryServerConfig.setListenerConfigs(inMemoryListenerConfig);
        directoryServerConfig.addAdditionalBindCredentials(securityPrincipal, securityCredentials);
        ldapServer = new InMemoryDirectoryServer(directoryServerConfig);

        ldapServer.startListening();

        com.unboundid.ldap.sdk.Entry wso2Entry = new com.unboundid.ldap.sdk.Entry(baseDN);
        wso2Entry.addAttribute("objectClass", "dcObject");
        wso2Entry.addAttribute("objectClass", "organizationalUnit");
        wso2Entry.addAttribute("ou", "WSO2");
        wso2Entry.addAttribute("dc", "WSO2");

        ldapServer.add(wso2Entry);

        com.unboundid.ldap.sdk.Entry entry = new com.unboundid.ldap.sdk.Entry(userBase);
        entry.addAttribute("objectClass", "organizationalUnit");
        ldapServer.add(entry);
    }


    public void deleteSampleEntry() throws Exception {
        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        env.put(Context.PROVIDER_URL, providerUrl);
        env.put(Context.SECURITY_PRINCIPAL, securityPrincipal);
        env.put(Context.SECURITY_CREDENTIALS, securityCredentials);

        DirContext ctx = new InitialDirContext(env);
        String dn = "uid=" + testUserId + "," + userBase;
        ctx.destroySubcontext(dn);
    }

    public static OMElement createOMElement(String xml) {
        try {
            XMLStreamReader reader = XMLInputFactory
                    .newInstance().createXMLStreamReader(new StringReader(xml));
            StAXOMBuilder builder = new StAXOMBuilder(reader);
            return builder.getDocumentElement();
        } catch (XMLStreamException e) {
            throw new RuntimeException(e);
        }
    }

    @AfterMethod
    protected void cleanup() {
        if (ldapServer != null) {
            ldapServer.shutDown(true);
        }
        ldapServer = null;
    }
}
