XML_PREFIX = "http://www.w3.org/2001/XMLSchema"
RDFS_PREFIX = "http://www.w3.org/2000/01"
RDFNS_PREFIX = "http://www.w3.org/1999/02"
OWL_PREFIX = "http://www.w3.org/2002/07"
SSM_PREFIX = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness"

class NQWriter:
    def __init__(self, nqfilestream):
        self.f = nqfilestream

    def set_graph(self, graph):
        self.g = graph
        
    def encode_boolean(self, b):
        if (b.lower() == "true"):
            return "\"true\"^^<{}#boolean>".format(XML_PREFIX)
        elif (b.lower() == "false"):
            return "\"false\"^^<{}#boolean>".format(XML_PREFIX)
        else:
            # print an error message or throw an exception
            print("Attempted boolean encoding of argument {}".format(b))
            raise ValueError("Bad argument type")
            
    def encode_integer(self, i):
        # Convert the string i to an int j, should throw an exception if i does not represent an int
        j = int(i)
            
        # return the xml encoding of an integer
        return "\"{}\"^^<{}#integer>".format(i, XML_PREFIX)

    def _encode_string(self, r):
        # not sure how to test whether something is a literal string
        
        # insert the quotation marks
        return "\"{}\"".format(r)

    def encode_string(self, param):
        if isinstance(param, str):
            return self._encode_string(param)
        else:
            return map(self._encode_string, param)

    def encode_rdfs_uri(self, r):
        # should check that the truncated URI starts rdf-schema#
        
        # this should be used to convert as follows:
        # - input: rdf-schema#fragment, output <RDFS_PREFIX/rdf-schema#fragment>
        
        # insert the prefix and encode as a URI
        if(r != ""):
            return "<{}/{}>".format(RDFS_PREFIX, r)
        else:
            return ""

    def encode_rdfns_uri(self, r):
        # should check that the truncated URI starts 22-rdf-syntax-ns#
        
        # this should be used to convert as follows:
        # - input: 22-rdf-syntax-ns#fragment, output <RDFNS_PREFIX/22-rdf-syntax-ns#fragment>
        
        # insert the prefix and encode as a URI
        if(r != ""):
            return "<{}/{}>".format(RDFNS_PREFIX, r)
        else:
            return ""

    def encode_owl_uri(self, r):
        # should check that the truncated URI starts 22-rdf-syntax-ns#
        
        # this should be used to convert as follows:
        # - input: owl#fragment, output <OWL_PREFIX/owl#fragment>
        
        # insert the prefix and encode as a URI
        if(r != ""):
            return "<{}/{}>".format(OWL_PREFIX, r)
        else:
            return ""
            
    def _encode_ssm_uri(self, r):
        # not sure how to test whether something is a string
        
        # this should be used to convert as follows:
        # - input: core#fragment, output <SSM_PREFIX/core#fragment>
        # - input: domain#fragment, output <SSM_PREFIX/domain#fragment>
        # - input: string, output <SSM_PREFIX/string>
        
        # insert the prefix and encode as a URI
        if(r != ""):
            return "<{}/{}>".format(SSM_PREFIX, r)
        else:
            return ""

    def encode_ssm_uri(self, param):
        if isinstance(param, str):
            return self._encode_ssm_uri(param)
        else:
            return map(self._encode_ssm_uri, param)

    def write_quad(self, d, p, r):
        self.f.write("{} {} {} {} .\n".format(d, p, r, self.g))
        
    def write_comment(self, s):
        self.f.write("# {}\n".format(s))
