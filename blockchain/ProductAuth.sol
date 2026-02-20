// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ProductAuth {

    struct Product {
        string productId;
        string manufacturer;
        string secureToken;
        bool isRegistered;
    }

    mapping(string => Product) private products;

    event ProductRegistered(string productId, string secureToken);

    function addProduct(
        string memory _productId,
        string memory _manufacturer,
        string memory _secureToken
    ) public {

        require(!products[_secureToken].isRegistered, "Already registered");

        products[_secureToken] = Product(
            _productId,
            _manufacturer,
            _secureToken,
            true
        );

        emit ProductRegistered(_productId, _secureToken);
    }

    function verifyProduct(string memory _secureToken)
        public
        view
        returns (
            string memory,
            string memory,
            bool
        )
    {
        Product memory p = products[_secureToken];

        return (
            p.productId,
            p.manufacturer,
            p.isRegistered
        );
    }
}
