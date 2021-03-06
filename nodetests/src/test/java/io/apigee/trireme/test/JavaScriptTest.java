package io.apigee.trireme.test;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RunWith(Parameterized.class)
public class JavaScriptTest
    extends TestBase
{
    public static final String[] BASE_DIRS =
        new String[] { "target/test-classes/test/simple",
                       "target/test-classes/test/noderunner",
                       "target/test-classes/test/pummel",
                       "target/test-classes/test/iconv" };
    public static final String TEMP_DIR = "target/test-classes/test/tmp";
    public static final String RESULT_FILE = "target/results.out";
    public static final String TEST_FILE_NAME_PROP = "TestFile";
    public static final String TEST_ADAPTER_PROP = "TestAdapter";

    public static final String NETTY_ADAPTER = "netty";

    private static final Pattern isJs = Pattern.compile(".+\\.js$");
    private static final Pattern isHttp = Pattern.compile("^test-http.+");
    private static final DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();

    private static PrintWriter resultWriter;

    @BeforeClass
    public static void setup()
        throws IOException
    {
        File tmpDir = new File(TEMP_DIR);
        if (!tmpDir.exists()) {
            // The parent dir should already have been created by Maven
            tmpDir.mkdir();
        }

        resultWriter = new PrintWriter(new FileOutputStream(RESULT_FILE));
    }

    @AfterClass
    public static void cleanup()
    {
        resultWriter.close();
    }

    /**
     * Figure out what tests to run by enumerating all the tests in the specified test directories,
     * then putting them on a list of tests to run using JUnit. That way we use the Node test suite but run it
     * in JUnit so that we can track results. We do it like this:
     * <ol>
     *     <li>Enumerate the ".js" files in the directory, or use the "TestFile" property to override</li>
     *     <li>Remove any tests that are on the excluded list, which is loaded from "excluded-tests.txt"</li>
     *     <li>Run any HTTP tests twice, once with native Node HTTP and once with Netty</li>
     * </ol>
     */

    @Parameterized.Parameters(name="{index}: {0} ({1}, {2})")
    public static Collection<Object[]> enumerateTests()
        throws IOException, SAXException, ParserConfigurationException
    {
        String testFile = System.getProperty(TEST_FILE_NAME_PROP);
        String adapter = System.getProperty(TEST_ADAPTER_PROP);
        Pattern namePattern;
        if (testFile == null) {
            namePattern = null;
        } else {
            if (isJs.matcher(testFile).matches()) {
                namePattern = Pattern.compile(".*" + testFile + "$");
            } else {
                namePattern = Pattern.compile(".*" + testFile + ".*\\.js$");
            }
        }

        ArrayList<File> files = new ArrayList<File>();
        for (String bd : BASE_DIRS) {
            File baseDir = new File(bd);
            final Collection<Pattern> excluded = loadExclusions(baseDir);
            final Pattern np = namePattern;
            File[] theseFiles = baseDir.listFiles(new FilenameFilter()
            {
                @Override
                public boolean accept(File file, String s)
                {
                    for (Pattern ep : excluded) {
                        // Yes, this is O(N*M). But for the number of exclusions it's fine.
                        if (ep.matcher(s).matches()) {
                            System.out.println("Skipping: " + s);
                            return false;
                        }
                    }
                    if (np == null) {
                        Matcher m = isJs.matcher(s);
                        return m.matches();
                    } else {
                        Matcher m = np.matcher(s);
                        return m.matches();
                    }
                }
            });
            if (theseFiles != null) {
                files.addAll(Arrays.asList(theseFiles));
            }
        }

        ArrayList<Object[]> ret = new ArrayList<Object[]>();
        if (files == null) {
            return ret;
        }
        for (File f : files) {
            for (String version : javaVersions) {
                if (adapter != null) {
                    ret.add(new Object[] { f, adapter, version });
                } else {
                    ret.add(new Object[] { f, DEFAULT_ADAPTER, version });
                    if (isHttp.matcher(f.getName()).matches()) {
                        ret.add(new Object[] { f, NETTY_ADAPTER, version });
                    }
                }
            }
        }
        return ret;
    }

    private static Collection<Pattern> loadExclusions(File baseDir)
        throws IOException, SAXException, ParserConfigurationException
    {
        ArrayList<Pattern> ret = new ArrayList<Pattern>();
        // Maybe by 2020 we can get JSON parsing built in to Java, but I am hesitant to pull in another dependency
        File ef = new File(baseDir, "excluded-tests.xml");
        if (!ef.exists()) {
            return ret;
        }

        FileInputStream exclusionFile = new FileInputStream(ef);
        try {
            DocumentBuilder builder = docFactory.newDocumentBuilder();
            Document exclusions =
                builder.parse(exclusionFile);

            Node top = exclusions.getDocumentElement();
            Node n = top.getFirstChild();
            while (n != null) {
                if ("Excluded".equals(n.getNodeName())) {
                    Node c = n.getFirstChild();
                    while (c != null) {
                        if ("Name".equals(c.getNodeName())) {
                            ret.add(Pattern.compile(getTextChildren(c)));
                        }
                        c = c.getNextSibling();
                    }
                }
                n = n.getNextSibling();
            }
            return ret;
        } finally {
            exclusionFile.close();
        }
    }

    private static String getTextChildren(Node n)
    {
        StringBuilder s = new StringBuilder();
        Node c = n.getFirstChild();
        while (c != null) {
            if ((c.getNodeType() == Node.TEXT_NODE) || (c.getNodeType() == Node.CDATA_SECTION_NODE)) {
                s.append(c.getNodeValue());
            }
            c = c.getNextSibling();
        }
        return s.toString();
    }

    public JavaScriptTest(File fileName, String adapter, String javaVersion)
    {
        super(fileName, adapter, javaVersion);
    }

    @Test
    public void testJavaScript()
        throws IOException, InterruptedException
    {
        System.out.println("**** Testing " + fileName.getName() + " (" + adapter + ", " + javaVersion + ")...");

        int exitCode = launchTest(DEFAULT_TIMEOUT, null, true);

        resultWriter.println(fileName.getName() + '\t' + adapter + '\t' + javaVersion + '\t' + exitCode);
        if (exitCode == 0) {
            System.out.println("** " + fileName.getName() + " (" + adapter + ", " + javaVersion + ") SUCCESS");
        } else {
            System.out.println("** " + fileName.getName() + " (" + adapter + ", " + javaVersion + ") FAILURE = " + exitCode);
        }
        assertEquals(fileName.getName() + " (" + adapter + ", " + javaVersion + ") failed with =" + exitCode,
                     0, exitCode);
    }
}

